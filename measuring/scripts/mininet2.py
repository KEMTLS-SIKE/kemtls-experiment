# Mininet simulation

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange
from mininet.cli import CLI

class BenchmarkTopo( Topo ):
    "Simple topology with latency."
    def __init__( self, latency="1ms", loss=0, rate=1):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        h1 = self.addHost('client')        
        h2 = self.addHost('server')

        h1.cmd("echo '{} server' >> /etc/hosts", h2.IP())

        s1 = self.addSwitch( 's1' )

        # Add links
        self.addLink(h1, s1)#, latency=latency, bw=rate, loss=loss)
        self.addLink(h2, s1)

net = Mininet(topo=BenchmarkTopo(),
                link=TCLink)
net.start()

print("Testing network connectivity")
net.pingAll()

CLI(net)


net.stop() 
