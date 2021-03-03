#!/usr/bin/python


from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.node import RemoteController,OVSKernelSwitch
from time import sleep


class Multipahtopo(Topo):
    "Single switch connected to n hosts."

    def build(self):
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch)
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch)
        s3 = self.addSwitch('s3', cls=OVSKernelSwitch)
        s4 = self.addSwitch('s4', cls=OVSKernelSwitch)
        s5 = self.addSwitch('s5', cls=OVSKernelSwitch)

        h1 = self.addHost('h1', mac="00:00:00:00:00:01", ip="10.0.0.1/24")
        h2 = self.addHost('h2', mac="00:00:00:00:00:02", ip="10.0.0.2/24")
        h3 = self.addHost('h3', mac="00:00:00:00:00:03", ip="10.0.0.3/24")
        h4 = self.addHost('h4', mac="00:00:00:00:00:04", ip="10.0.0.4/24")

        self.addLink(s1, s2, 1, 1)
        self.addLink(s1, s3, 2, 1)

        self.addLink(s2, s5, 2, 1)
        self.addLink(s3, s4, 2, 1)
        self.addLink(s4, s5, 2, 2)


        self.addLink(h1, s1, 1, 3)
        self.addLink(h2, s1, 1, 4)
        self.addLink(h3, s5, 1, 3)
        self.addLink(h4, s5, 1, 4)


if __name__ == '__main__':
    setLogLevel('info')
    topo = Multipahtopo()
    c1 = RemoteController('c1', ip='127.0.0.1')
    net = Mininet(topo=topo, controller=c1)
    net.start()
    # to avoid arp broadcasts when we generally do h1 ping h2
    #then h1 will do the arp to get mac of h2 we are not dealing with this broadcasr 
    # static arp  means that directly macs are known to each other
    net.staticArp()
    sleep(20)
    # get the host objects
    print("some ping packets are generated")
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    h1.cmd('ping -c3 10.0.0.2 -W 1')
    h2.cmd('ping -c3 10.0.0.3 -W 1')
    h3.cmd('ping -c3 10.0.0.4 -W 1')
    h4.cmd('ping -c3 10.0.0.1 -W 1')
    #sleep(1)
    #net.pingAll()
    #net.pingAll()
    CLI(net)
    net.stop()
