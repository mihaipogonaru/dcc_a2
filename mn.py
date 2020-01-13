#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def ch2Net():
	CONTROLLER_IP = '192.168.155.6' # <=== TODO: CONTROLLER IP HERE!
	
	net = Mininet(topo=None, build=False, )
	
	c1 = net.addController('c1', controller=RemoteController, ip=CONTROLLER_IP, port=6653)

	h1 = net.addHost('h1', ip='10.1.0.1/24')
	h2 = net.addHost('h2', ip='10.1.0.2/24', mac='00:de:ad:be:ef:00')
	h3 = net.addHost('h3', ip='10.1.0.2/24', mac='00:de:ad:be:ef:00')

	s1 = net.addSwitch('s1')
	
	net.addLink(h1, s1)
	net.addLink(h2, s1)
	net.addLink(h3, s1)

	net.build()
	
	s1.start([c1])
	
	#h2.cmdPrint('systemctl start apache2@h2')
	#h2.cmdPrint('/etc/init.d/apache2-h2 start')
	#h3.cmdPrint('systemctl start apache2@h3')
	#h3.cmdPrint('/etc/init.d/apache2-h3 start')

	h2.cmdPrint('APACHE_CONFDIR=/etc/apache2-h2 APACHE_STARTED_BY_SYSTEMD=false /usr/sbin/apachectl start')
	h3.cmdPrint('APACHE_CONFDIR=/etc/apache2-h3 APACHE_STARTED_BY_SYSTEMD=false /usr/sbin/apachectl start')

	CLI( net )

        h2.cmdPrint('APACHE_CONFDIR=/etc/apache2-h2 APACHE_STARTED_BY_SYSTEMD=false /usr/sbin/apachectl stop')
	h3.cmdPrint('APACHE_CONFDIR=/etc/apache2-h3 APACHE_STARTED_BY_SYSTEMD=false /usr/sbin/apachectl stop')

	net.stop()

if __name__ == '__main__':
	setLogLevel( 'info' )
	ch2Net()
	
