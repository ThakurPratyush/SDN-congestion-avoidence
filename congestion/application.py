from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.lib.packet import ipv4
from ryu.lib.ovs import bridge
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import hub
from time import sleep
import networkx as nx
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host
#ovs details
OVSDB_ADDR = "tcp:127.0.0.1:6640"


CONGESTION_CONTROL = 1

queues = []

INTERVAL = 10

DISCOVERY_INERVAL = 60
TOPOLOGY_DISCOVERED = 0


QUEUE_IGNORE_LIST = {1:[3,4],5:[3,4]}

# to store the data rate corresponding to a particular flow
keystore = {}

def calculate_value(key, val):
    '''
    store the val in kv. and calcualte the rate per sec
    '''
    if key in keystore:
        oldval = keystore[key]
        cval = (val - oldval) / INTERVAL
        # storing the val
        keystore[key] = val
        return cval
    else:
        keystore[key] = val
        return 0


class QoSSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(QoSSwitch, self).__init__(*args, **kwargs)
        self.datapaths = {}
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('congestion_control', default=0, help = ('Congestion Control')),
            cfg.IntOpt('link_bandwidth', default=5000, help = ('tcp bandwidth in Kbps')),
            ])
        self.logger.info(CONF)
        self.mac_to_port = {}
        self.PORT_SPEED = 100 * 1000000    # 100 Mbps
        self.TCP_RATE = CONF.link_bandwidth * 1000    #convert in to bits 
        self.congestion_control = CONF.congestion_control
        self.logger.info("Application starts with PORT_Bandwidth %s  link_bandwidth %s, Congestion-Control %s",  self.PORT_SPEED , CONF.link_bandwidth, self.congestion_control)

        self.TCP_QUEUE_INDEX = 0
        #self.UDP_QUEUE_INDEX = 1

        #self.queues = [0,0]
        self.queues = [0]
        self.queues[self.TCP_QUEUE_INDEX] = {"max-rate": str(self.TCP_RATE), "min-rate": "0"}
        if CONGESTION_CONTROL:
            self.monitor_thread = hub.spawn(self._monitor)

        self.topology_api_app = self
        self.topodiscovery_thread = hub.spawn(self._tdiscovery)    
        self.hosts = []
        self.links = []
        self.switches = []

    def update_congestion(self, dpid, port, qerror):
        
        #link looks like
        #(1, 2, {'port': x, 'congestion': 1})
        #here saying that switch 1 is connected to switch 2 via port x
        #print(self.links)

        for link in self.links:
            if dpid == link[0] and link[2]['port'] == port:
                #print("Updated congestion ", dpid, "port", port, "value", qerror)
                link[2]['congestion'] = qerror
                return

    def _monitor(self):
        hub.sleep(DISCOVERY_INERVAL)
        while True:
            self.logger.info("Congestion Detection and avoidence ........")
            for dp in self.datapaths.values():
                self.collect_queue_metrics(dp)
            hub.sleep(1)
            self.build_topology()
            hub.sleep(INTERVAL)

    def collect_queue_metrics(self, datapath):
        self.logger.info(" datapath being queried %s", datapath.id)
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPQueueStatsRequest(datapath, 0, ofp.OFPP_ANY,ofp.OFPQ_ALL)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPQueueStatsReply, MAIN_DISPATCHER)
    def queue_reply_handler(self, ev):
        #self.logger.info("queue reply handler %s", ev.msg.body)
        #ev.msg.datapath.id
        dpid = ev.msg.datapath.id
        queues = []
        for stat in ev.msg.body:
            if stat.queue_id == 0:
                #port_no=1,queue_id=1,tx_bytes=0,tx_packets=0,tx_errors=0
                hdr = "switch_" + str(dpid) + "_" + str(stat.port_no) + "_queue" + str(stat.queue_id)
                qerrors = calculate_value(hdr, int(stat.tx_errors))
                self.update_congestion(dpid, stat.port_no, qerrors)

    def _tdiscovery(self):
        global TOPOLOGY_DISCOVERED
        #while True:
        hub.sleep(DISCOVERY_INERVAL)
        self.get_topology_data()
        TOPOLOGY_DISCOVERED = 1

    def build_topology(self):
        self.networkx = None
        self.networkx = nx.DiGraph()
        #print(self.links)
        for s in self.switches:
            self.networkx.add_node(s, name=s)
        for l in self.links: 
            #print(l)
            if l[2]['congestion'] == 0:
                w = 1
            else:
                w = 100
            print("Updateed link  ", l[0], l[1], "has new weight", w )
            self.networkx.add_edge(l[0],l[1],weight=w)

    def get_topology_data(self):        
        switch_list = get_switch(self.topology_api_app, None)
        self.switches = [switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        self.links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no, 'congestion': 0}) for link in links_list]
        host_list = get_host(self.topology_api_app, None)
        self.hosts = [(host.mac, host.port.dpid, {'port': host.port.port_no}) for host in host_list]
        self.logger.info("**********************Topology Discovery Data *******************************")
        self.logger.info("switches %s", self.switches)
        self.logger.info("links %s", self.links)
        self.logger.info("hosts %s", self.hosts)
        self.logger.info("*****************************************************************************")
        self.build_topology()

    

    def get_dpid(self,mac):
        '''                
        returns the specific host data from the topology discovered hosts
        # host
        #('00:00:00:00:00:01', 10, {'port': 4})
        '''        
        for host in self.hosts:
            if host[0] == mac:
                return host


    def get_portnumber(self,srcdpid,dstdpid):
        for link in self.links:
            if link[0]==srcdpid and link[1]==dstdpid:
                return link[2]["port"]

    def prepareflow(self, dpid, smac, dmac, outport,srcip,dstip, qid=None):
        datapath = self.datapaths[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_dst=dmac, eth_src=smac,eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=srcip, ipv4_dst=dstip)
        actions = [parser.OFPActionOutput(outport)]

        if qid != None:
            actions.append(parser.OFPActionSetQueue(qid))
        self.add_flow(datapath, 10, match, actions)



    def find_spf(self,srcmac,dstmac, srcip, dstip):
        '''
        Todo

        '''
        self.logger.info("shortest weight path calculated and also flows added along the path ")
        self.logger.info("Caculating shortest path between  %s to %s" , srcmac , dstmac)
        #  Switch connected to Source Host in variable result
        result = self.get_dpid(srcmac)
        srcdpid = result[1]
        #  Switch connected to Destination Host
        result = self.get_dpid(dstmac)
        dstdpid = result[1]#destination switch and port are now available
        dstport = result[2]
        # Add a flow in the switch which is connected to the destination host 

        # shortest path between switches srcdpd nd dstdpid 
	#weight is used to characterize the variable we used to assign weights (1 or 100)
        paths = nx.dijkstra_path(self.networkx, srcdpid, dstdpid, weight="weight")
  

        self.logger.info("paths obtained %s",paths)
        #get port number for each path:
        index = 0
        length = len(paths)
        for x in range(0,length-1):
            srcdpid = paths[x]
            nexthop = paths[x+1]
            self.logger.info('source port %d destination port %d ', srcdpid, nexthop)
            port = self.get_portnumber(srcdpid, nexthop)
            self.logger.info("port %d", port)
            path = {"destination source id": srcdpid, "source mac adress":srcmac, "destination mac adress": dstmac, "port used": port}
	    #prepare flow called to prepare the flows for the match and actions at switches
            self.prepareflow(srcdpid, srcmac, dstmac, port, srcip, dstip, self.TCP_QUEUE_INDEX)

        # Add a flow in the switch which is connected to the destination host             
        # As this is destination switch can be obtained by the dstport directly
        self.prepareflow(dstdpid, srcmac, dstmac, dstport['port'], srcip, dstip)
        
 

        self.logger.info("completion of path caluation and flow addition")

        #check whether both srchost and dsthost connected on same switch then return the port
        if srcdpid == dstdpid:
            return dstport['port']


        srcdpid = paths[0]
        nexthop = paths[1]
#sleep to allow the addition of flow time
        sleep(0.2)        
        port = self.get_portnumber(srcdpid, nexthop)
        return port


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        #self.add_flow(datapath, 0, 0, match, actions)
        self.add_flow(datapath, 0, match, actions,idle_t=0, hard_t=0)
        self.apply_qos(datapath.id)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_t=30, hard_t=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, idle_timeout=idle_t, hard_timeout=hard_t,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle_t, hard_timeout=hard_t,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)



    def apply_qos(self, dpid):
        '''
        Logic:
        1. Establish the communication with ovsdb using RYU ovsbridge library
        2. Apply the Queuing in all the ports
        '''
        self.logger.info("apply_qos called with: dpid %s portspeed %s", dpid, self.PORT_SPEED)
        ovs_bridge = bridge.OVSBridge(CONF=self.CONF, datapath_id=dpid,
                                      ovsdb_addr=OVSDB_ADDR)
        try:
            ovs_bridge.init()
        except:
            raise ValueError('ovsdb addr is not available.')

        # find port name 
        names = ovs_bridge.get_port_name_list()
        for name in names:
            port_id = ovs_bridge.get_ofport(name)

            if dpid in QUEUE_IGNORE_LIST:
                if port_id in QUEUE_IGNORE_LIST[dpid]:
                    continue

            self.logger.info("queues %s", self.queues)
            result = ovs_bridge.set_qos(name, type='linux-htb',
                                        max_rate=str(self.PORT_SPEED),
                                        queues=self.queues)
            self.logger.info("ouput %s ", result)
            self.logger.info("Applied the Qos switch %s,  port %s queue %s ", dpid, name, self.queues)
        return


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        #self.logger.info("packet in %s src %s dst %s in_port %s type %s", dpid, src, dst, in_port,eth.ethertype)

        #Do not process any packet before topology discovery
        if not TOPOLOGY_DISCOVERED:
            #self.logger.info("Dropping the packet...Topology discovery inprogress")
            return
        
        #DROP BROADCAST and IPv6 MULICAST Packe
        if dst == "ff:ff:ff:ff:ff:ff" or dst[:5] == "33:33":
            #self.logger.info("drop ipv6 multicast packet %s", dst)
            return

        # check IP Protocol and create a match for IP
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            srcip = ip.src
            dstip = ip.dst                        
            oport = self.find_spf(src,dst, srcip, dstip)
            if oport:
                actions = []
                actions.append(parser.OFPActionOutput(oport))
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                        in_port=in_port, actions=actions, data=msg.data)
                datapath.send_msg(out)            
