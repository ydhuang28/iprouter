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
		self.interfaces = self.net.interfaces()

	def _has_interface(self, arp):
		'''
		(self, Arp) -> (bool, IPv4Addr, Arp)

		Checks whether we need to respond to the ARP request.
		'''
		if arp.targetprotoaddr in self.interfaces:
			return True, arp.targetprotoaddr, arp
		else:
			return False, None, None

	def _create_and_send_arp_reply(self, need_resp, target, arp_req):
		'''
		(self, bool, IPv4Addr, Arp) -> ()

		Sends an ARP reply if needed.
		'''
		if need_resp:
			arp_reply = create_ip_arp_reply(arp_req.senderhwaddr,
											arp.req.targethwaddr,
											arp.req.senderprotoaddr,
											intf.ipaddr)
			self.net.send_packet(port_by_ipaddr(target), arp_reply)


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
				if arp not None:
					need_resp, targetip, arp_req = _has_interface(arp)
					_create_and_send_arp_reply(self, need_resp, targetip, arp_req)
		
				

def switchy_main(net):
	'''
	(PyLLNet) -> ()

	Main entry point for router.  Just create Router
	object and get it going.
	'''
	r = Router(net)
	r.router_main()
	net.shutdown()
