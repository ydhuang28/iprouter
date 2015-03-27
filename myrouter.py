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
import queue
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *

class Router(object):
	def __init__(self, net):
		'''
		(PyLLNet) -> ()

		Initializes the router object.
		'''
		self.net = net
		self.interfaces = self.net.interfaces()
		self.arpcache = {}
		self.arpqueue = queue.Queue()
		self.fwdtable = {}
		self.fill_fwdtable()
		
	def fill_fwdtable(self):
		'''
		() -> ()

		Populates the forwarding table.

		Every entry in the forwarding table is a list consisting of
		(prefixnet, nexthop) tuples representing all prefixes associated
		with that interface.
		
		The table is keyed by each interface's name.
		'''
		for intf in self.interfaces: # initially the table contains interfaces only
			# set nexthop for our own interfaces to null (no need to forward)
			prefixnet = IPv4Network(str(intf.ipaddr) + "/" + str(intf.netmask))
			self.fwdtable[intf.name] = [(prefixnet, IPv4Address(0))]

		forwarding_table = open('forwarding_table.txt')
		for line in forwarding_table:
			temp = line.split(' ')
			prefixnet = IPv4Network(temp[0] + "/" + temp[1])
			nexthop = IPv4Address(temp[2])
			intf = temp[3]

			if intf in self.fwdtable:
		 		self.fwdtable[intf] += [(prefixnet, nexthop)]
			else:
		 		self.fwdtable[intf] = [(prefixnet, nexthop)]

		forwarding_table.close()

	def got_reply(self, arp):
		'''
		(Arp) -> (bool)
		'''
		for interface in self.


	def fwdtable_lookup(self, ipv4):
		'''
		(IPv4) -> (str, int)

		Looks up a certain IPv4 address in the forwarding table,
		returning the entry in the table.

		The keys to the table are interfaces and the integer
		specifies which item to look for in the list of network prefixes
		associated with the interface in question.
		'''
		dst_ipaddr = IPv4Address(ipv4.dst)
		possible_prefixes = []
		for intf in self.fwdtable.keys():				# every interface in forwarding table
			for i in range(len(self.fwdtable[intf])):	# every prefix asc.'d w/ the interface
				prefixnet, nexthop = self.fwdtable[intf][i]
				if str(nexthop) == '0.0.0.0':	# one of our interfaces, dropping
					return None, -2
				if dst_ipaddr in prefix:
					possible_prefixes += [(prefixnet, intf, i)]

		if len(possible_prefixes) == 0:
			return None, -1

		# look for most precise prefix
		most_precise_prefix = possible_prefixes[0][0]
		for prefix in possible_prefixes:
			curr_prefixlen = prefix[0].prefixlen
			if most_precise_prefix.prefixlen < curr_prefixlen:
				most_precise_prefix = prefix

		return most_precise_prefix[1:]

	def ready_packet(self, intf, ind, pkt):
		'''
		Precondition: pkt has IPv4 header
		'''
		ipv4 = pkt[1]
		ipv4.ttl -= 1

		eth = pkt[0]
		eth.src = intf.ethaddr

		# check ARP cache
		if ipv4.dstip in self.arpcache:
			eth.dst = self.arpcache[ipv4.dstip]
			self.net.send_packet(intf, pkt)
		else:	# create ARP request
			arppacket = create_arp_req(intf, ipv4.dstip)
			self.net.send_packet(intf, arppacket)
			senttime = time.time()
			queue_pkt = ARPQueuePacket(pkt)
			queue_pkt.update_rqst_time(senttime)
			self.arpqueue.put(queue_pkt)

	def send_enqueued_packets(self):


	def create_arp_req(self, intf, targetip):
		ether = Ethernet()
		ether.src = intf.ethaddr
		ether.dst = 'ff:ff:ff:ff:ff:ff'
		ether.ethertype = EtherType.ARP
		arp_req = Arp()
		arp.operation = ArpOperation.Request
		arp.senderhwaddr = intf.ethaddr
		arp.senderprotoaddr = intf.ipaddr
		arp.targethwaddr = 'ff:ff:ff:ff:ff:ff'
		arp.targetprotoaddr = targetip
		arppacket = ether + arp

		return arppacket


	def router_main(self):    
		'''
		() -> ()

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
				log_info("Got a packet: {}".format(str(pkt)))
				
				arp = pkt.get_header(Arp)
				ipv4 = pkt.get_header(IPv4)
				if arp != None:		# has ARP header
					if arp.targetprotoaddr == dev.ipaddr
						if arp.targethwaddr == 'ff:ff:ff:ff:ff:ff':	# need to reply
							arp_reply = create_ip_arp_reply(dev.ethaddr,
															arp.senderhwaddr,
															dev.ipaddr,
															arp.senderprotoaddr)
							self.net.send_packet(dev, arp_reply)
						else: # got reply
							self.arpcache[arp.senderprotoaddr] = arp.senderhwaddr
							self.send_enqueued_packets()
					else:
						log_info("ARP request not for us, dropping: {}".format(str(pkt)))
				elif ipv4 != None:	# has IPv4 header
					intf, index = self.fwdtable_lookup(ipv4)
					if index != -1:	# has a match
						self.ready_packet(intf, index, pkt)
					elif index == -1:	# no match
						log_info("No match in fwding table, dropping: {}".format(str(pkt)))
					else:	# index == -2, our packet; drop it for now
						log_info("Packet for us, dropping: {}".format(str(pkt)))
				else:
					log_info("Got packet that is not ARP or IPv4, dropping: {}".format(str(pkt)))

class ARPQueuePacket(object):
	def __init__(self, pkt):
		self.pkt = pkt
		self.retries = 0
		self.last_request = time.time()

	def is_dead(self):
		return self.retries > 5

	def update_rqst_time(self, time)
		self.last_resend = time

def switchy_main(net):
	'''
	(PyLLNet) -> ()

	Main entry point for router.  Just create Router
	object and get it going.
	'''
	r = Router(net)
	r.router_main()
	net.shutdown()
