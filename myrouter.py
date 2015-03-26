#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.

Collaborators: Yuxin David Huang, Martin Liu' 16
Under supervision of Prof. Joel Sommers
COSC 465 (Spring 2015), Colgate University
'''

import sys
import os
import time
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *

class Router(object):
	def __init__(self, net):
		'''
		(self, PyLLNet) -> ()

		Initializes the router object.
		'''
		self.net = net
		self._interfaces = self.net.interfaces()
		self._arptable = {}		# for later use, do nothing for now
		for intf in self.interfaces: #initially the table contains interfaces only
			self._arptable[intf.name] = [(intf.ipaddr, intf.netmask, 0,0,0,0)]

		forwarding_table = open('forwarding_table.txt')
		for line in forwarding_table:
			temp = line.split(' ')
			if temp[3] in self._arptable:
		 		self._arptable[temp[3]].append((temp[0],temp[1],temp[2])) 
			else:
		 		self._arptable[temp[3]] = (temp[0],temp[1],temp[2])

		forwarding_table.close()

	def _has_interface(self, arp):
		'''
		(self, Arp) -> (bool, IPv4Addr, Arp)

		Checks whether we need to respond to the ARP request.
		'''
		if arp.targetprotoaddr in self._interfaces:
			return True, arp.targetprotoaddr, arp
		else:
			return False, None, None

	def _fwdtable_lookup(self, ipv4):
		dst_ipaddr = IPv4Network(ipv4.dst)
		for intf in list(self._arptable.keys()): #intf is the name of the interface
			temp_IPs = [] # a list of IPv4 Obj's
			for i in len(self._arptable[intf]):
				prefix = IPv4Network(self._arptable[intf][i][0] + "/" + self._arptable[intf][i][1])
				if (int(dst_ipaddr) & int(prefix)) == int(prefix):
					return  intf, i

	def _create_and_send_arp_reply(self, need_resp, targetip, arp_req):
		'''
		(self, bool, IPv4Addr, Arp) -> ()

		Sends an ARP reply if needed.
		'''
		if need_resp:
			arp_reply = create_ip_arp_reply(arp_req.senderhwaddr,
											arp.req.targethwaddr,
											arp.req.senderprotoaddr,
											targetip)
			self.net.send_packet(port_by_ipaddr(targetip), arp_reply)




	def router_main(self):    
		'''
		(self) -> ()

		Main method for router; we stay in a loop in this method, receiving
		packets until the end of time.
		'''
		while True:
			gotpkt = True
			try:
				dev, pkt = self.net.recv_packet(timeout=1.0)
			except NoPackets:
				log_debug("No packets available in recv_packet")
				gotpkt = False
			except Shutdown:
				log_debug("Got shutdown signal")
				break

			if gotpkt:
				log_debug("Got a packet: {}".format(str(pkt)))

				arp = pkt.get_header(Arp)
				ipv4 = pkt.get_header(IPv4)
				if arp is not None:
					need_resp, targetip, arp_req = _has_interface(arp)
					_create_and_send_arp_reply(self, need_resp, targetip, arp_req)
					if need_resp:
						arp_reply = self._create_arp_reply(targetip, arp_req, self.net.port_by_name(dev))
						self.net.send_packet(dev, arp_reply)
						
				elif ipv4 is not None:
					intf, index = _fwdtable_lookup(ipv4)
					print(intf)



		
				

def switchy_main(net):
	'''
	(PyLLNet) -> ()

	Main entry point for router.  Just create Router
	object and get it going.
	'''
	r = Router(net)
	r.router_main()
	net.shutdown()
