#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *

class Router(object):
	def __init__(self, net):
		self.net = net
		# other initialization stuff here







	def create_and_send_arp_reply(self, need_resp, intf, arp_req):
		if need_resp:
			arp_reply = create_ip_arp_reply(arp_req.senderhwaddr,
											arp.req.targethwaddr,
											arp.req.senderprotoaddr,
											intf.ipaddr)
			self.net.send_packet(arp_reply)


	def router_main(self):    
		'''
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

				# martin's method

				need_resp, intf, arp_req = m_method(pkt)
				create_and_send_arp_reply(self, need_resp, intf, arp_req)



def switchy_main(net):
	'''
	Main entry point for router.  Just create Router
	object and get it going.
	'''
	r = Router(net)
	r.router_main()
	net.shutdown()
