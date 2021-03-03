from ryu import cfg
# calling the dispatchers from switches
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.lib.packet import ipv4
from ryu.lib.ovs import bridge
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
# specific to using protocol data packets
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import hub
# calling sleep timer
from time import sleep
#creating a directed graph from switches using networkx
import networkx as nx
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host
#ovs details
OVSDB_ADDR = "tcp:127.0.0.1:6640"


sleep_time = 60
topo_detected = 0
queue_list = []
#10 seconds we send request for polling
duration = 10
#ports where queues are not made
left_ports = {1:[3,4],5:[3,4]}


error_value_dict = {}

def calc_error(k, v):
    '''
    store the val in kv. and calcualte the rate per sec
    '''
    if k in error_value_dict:
        old = error_value_dict[k]
        total = (v - old) / duration
        # storing the val
        error_value_dict[k] = v
        return total
    else:
        error_value_dict[k] = v
        return 0


class QoSSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        #default implentation provided in ryu to initialize the queues at switches
        super(QoSSwitch, self).__init__(*args, **kwargs)
        self.datapaths = {}
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('congestion avoidence', default=0, help = ('Congestion avoidence')),
            cfg.IntOpt('link bandwidth', default=5000, help = ('bandwidth'))])
        self.logger.info(CONF)
        self.mac_to_port = {}
        self.PORT_SPEED = 100 * 1000000    
        self.TCP_RATE = CONF.link_bandwidth * 1000   
        self.congestion_control = CONF.congestion_control
        self.logger.info("INITIAL VALUES OF RATE %s  link rate %s, Congestion avoidence %s",  self.PORT_SPEED , CONF.link_bandwidth, self.congestion_control)

        self.TCP_QUEUE_INDEX = 0
        self.queue_list = [0]
        self.queue_list[self.TCP_QUEUE_INDEX] = {"maximum  rate allowed in the queue": str(self.TCP_RATE), "minimum rate set": "0"}
        #self.queue_list[self.UDP_QUEUE_INDEX] = {"max-rate": str(self.UDP_RATE), "min-rate": "0"}
        self.monitor_thread = hub.spawn(self._monitor)
        self.topology_api_app = self
        self.topodiscovery_thread = hub.spawn(self.topo_detection)
        # corresponding to each switch these given variables are initialzed
        self.hosts = []
        self.links = []
        self.switches = []

    def assign_congestion_values(self, dpid, port, tx_err):
        # link set : example(1, 3, {'port': 2, 'congestion': 1}) by default congestion is 1 
        for link in self.links:
            if dpid == link[0] and link[2]['port'] == port:
                link[2]['congestion'] = tx_err
                return
    def shortest_path(self,srcmac,dstmac, srcip, dstip):

        self.logger.info("path calculation according to the weight given and addition of flows")
        self.logger.info("shortest path  from switch %s to %s" , srcmac , dstmac)
        result = self.get_switch_num(srcmac)
        srcdpid = result[1]
        result = self.get_switch_num(dstmac)
        dstdpid = result[1]
        dstport = result[2]
        # Add a flow in the switch which is connected to the destination host 
        #path having least weight is calculated by using the weights assigned
        paths = nx.dijkstra_path(self.networkx, srcdpid, dstdpid, weight="weight")
        self.logger.info("returned new paths : %s",paths)
        length = len(paths)
        for x in range(0,length-1):
            srcdpid = paths[x]
            nexthop = paths[x+1]
            self.logger.info('port from source %d destination %d ', srcdpid, nexthop)
            port = self.return_port_num(srcdpid, nexthop)
            self.logger.info("port %d", port)
            path = {"destionation switch": srcdpid, "source switch ":srcmac, "destination": dstmac, "port number taken ": port}
            self.prepareflow(srcdpid, srcmac, dstmac, port, srcip, dstip, self.TCP_QUEUE_INDEX)

        # destination port is added according to the dstport variable
        self.prepareflow(dstdpid, srcmac, dstmac, dstport['port'], srcip, dstip)
        

        self.logger.info("End of path calculation and flow addition")

        #if souce and destination switch are same then return dstport
        if srcdpid == dstdpid:
            return dstport['port']
        srcdpid = paths[0]
        nexthop = paths[1]
        sleep(0.5)        
        port = self.return_port_num(srcdpid, nexthop)
        return port


    def _monitor(self):
        #default function to start the threads
        hub.sleep(sleep_time)
        while True:
            self.logger.info("Program for congestion avoidence begins :")
            for dp in self.datapaths.values():
                self.qstats_values(dp)
            hub.sleep(1)
            self.build_topology()
            hub.sleep(duration)

    def qstats_values(self, datapath):
        self.logger.info(" querying the datapath %s", datapath.id)
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        # request message 
        req = ofp_parser.OFPQueueStatsRequest(datapath, 0, ofp.OFPP_ANY,ofp.OFPQ_ALL)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPQueueStatsReply, MAIN_DISPATCHER)
    def queue_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        queue_list = []
        for val in ev.msg.body:
            if val.queue_id == 0:
                header = "switch " + str(dpid) + "_" + str(val.port_no) + "_queue" + str(val.queue_id)
                tx_errs = calc_error(header, int(val.tx_errors))
                self.assign_congestion_values(dpid, val.port_no, tx_errs)

    def topo_detection(self):
        global topo_detected
        hub.sleep(sleep_time)
        self.get_topology_data()
        topo_detected = 1

    def build_topology(self):
        self.networkx = None
        self.networkx = nx.DiGraph()
        for switch in self.switches:
            self.networkx.add_node(switch, name=switch)
        for link in self.links: 
            if link[2]['congestion'] == 0:
                w = 1ink
            else:
                w = 100
            print("new weights assigned", link[0], link[1], "weight", w )
            self.networkx.add_edge(link[0],link[1],weight=w)

    def get_topology_data(self):        
        switch_list = get_switch(self.topology_api_app, None)
        self.switches = [switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        self.links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no, 'congestion': 0}) for link in links_list]
        host_list = get_host(self.topology_api_app, None)
        self.hosts = [(host.mac, host.port.dpid, {'port': host.port.port_no}) for host in host_list]
        self.logger.info("Topology discovery starts using the sample ping packets")
        self.logger.info("switches detected%s", self.switches)
        self.logger.info("links detected%s", self.links)
        self.logger.info("hosts detected%s", self.hosts)
        self.logger.info("end")
        self.build_topology()

    

    def get_switch_num(self,mac):
        '''                
        rhost data is returned by the function
        #host is set here 
        #host : ('00:00:00:00:00:03', 2, {'port': 2})
        '''        
        for host in self.hosts:
            if host[0] == mac:
                return host


    def return_port_num(self,srcdpid,dstdpid):
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




    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        #default function 
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
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
      
        self.logger.info("function called with: dpid %s port speed %s", dpid, self.PORT_SPEED)
        ovs_bridge = bridge.OVSBridge(CONF=self.CONF, datapath_id=dpid,
                                      ovsdb_addr=OVSDB_ADDR)
        try:
            ovs_bridge.init()
        except:
            raise ValueError('address not availble')
 
        names = ovs_bridge.get_port_name_list()
        for name in names:
            port_id = ovs_bridge.get_ofport(name)

            if dpid in left_ports:
                if port_id in left_ports[dpid]:
                    continue

            self.logger.info("queue lists formed at a port %s", self.queue_list)
            result = ovs_bridge.set_qos(name, type='linux-htb',
                                        max_rate=str(self.PORT_SPEED),
                                        queue_list=self.queue_list)
            self.logger.info("ouput obtained %s ", result)
            self.logger.info("values applied to switch %s,  port %s queue %s ", dpid, name, self.queue_list)
        return


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("only %s of %s bytes taken",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore packets for the topology discovery
            return
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        #Do not process any packet before topology discovery
        if not topo_detected:
            return
        
        #broadcast packets are removed
        if dst == "ff:ff:ff:ff:ff:ff" or dst[:5] == "33:33":
            return

        # if ip packets are there then we have to add flows
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            srcip = ip.src
            dstip = ip.dst                        
            oport = self.shortest_path(src,dst, srcip, dstip)
            if oport:
                actions = []
                actions.append(parser.OFPActionOutput(oport))
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                        in_port=in_port, actions=actions, data=msg.data)
                datapath.send_msg(out)            
