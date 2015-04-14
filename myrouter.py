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

		# in the forwarding table, a next hop of '0.0.0.0' is a directly
		# connected network. but that is probably bad design.
		self.fwdtable = {}
		self.fill_fwdtable()
		self.arpcache = {}
		self.arpqueue = queue.Queue()
		
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
			# set nexthop for directly connected network to null (no need to forward)
			prefixnet = IPv4Network(str(intf.ipaddr) + "/" + str(intf.netmask), strict=False)
			self.fwdtable[intf.name] = [(prefixnet, IPv4Address(0))]

		forwarding_table = open('forwarding_table.txt')
		for line in forwarding_table:
			temp = line.strip('\n').split(' ')
			prefixnet = IPv4Network(temp[0] + "/" + temp[1])
			nexthop = IPv4Address(temp[2])
			intf = temp[3]

			if intf in self.fwdtable:
		 		self.fwdtable[intf] += [(prefixnet, nexthop)]
			else:
		 		self.fwdtable[intf] = [(prefixnet, nexthop)]

		forwarding_table.close()

	def fwdtable_lookup(self, ipv4):
		'''
		(IPv4) -> (str, int)

		Looks up a certain IPv4 address in the forwarding table,
		returning the entry in the table.

		The keys to the table are interfaces and the integer
		specifies which item to look for in the list of network prefixes
		associated with the interface in question.
		'''
		dst_ipaddr = IPv4Address(ipv4.dstip)
		most_precise_prefix = (None, None, -1, None)
		for intf in self.fwdtable.keys():				# every interface in forwarding table
			if str(intf.ipaddr) == ipv4.dstip:			# ourselves
				return (ipv4.dstip, -2, ipv4.dstip)		# -2 for ourselves
			for i in range(len(self.fwdtable[intf])):	# every prefix asc.'d w/ the interface
				prefixnet, nexthop = self.fwdtable[intf][i]
				if dst_ipaddr in prefixnet:
					if most_precise_prefix[0] == None:
						most_precise_prefix = (prefixnet, intf, i, nexthop)
					elif most_precise_prefix[0].prefixlen < prefixnet.prefixlen:
						most_precise_prefix = (prefixnet, intf, i, nexthop)

		return most_precise_prefix[1:]

	def ready_packet(self, intf_name, pkt, nexthop):
		'''
		(str, Packet, IPv4Address) -> ()

		Precondition: pkt has IPv4 header.

		Readies an IPv4 packet to be sent. If the nexthop
		is already in the ARP cache, this will send the
		packet to next hop. If not, it will place the packet
		in a queue to wait for ARP requests.
		'''
		intf = self.net.interface_by_name(intf_name)

		ipv4 = pkt[pkt.get_header_index(IPv4)]
		ipv4.ttl -= 1

		eth = pkt[pkt.get_header_index(Ethernet)]
		eth.src = intf.ethaddr

		if str(nexthop) == "0.0.0.0":	# directly connected network
			nexthop = ipv4.dstip

		# check ARP cache
		if nexthop in self.arpcache:
			eth.dst = self.arpcache[nexthop]
			self.net.send_packet(intf.name, pkt)
		else:	# create ARP request
			arppacket = self.create_arp_req(intf, nexthop)
			self.net.send_packet(intf.name, arppacket)
			senttime = time.time()

			queue_pkt = ARPQueuePacket(pkt, intf)
			queue_pkt.update_rqst_time(senttime)
			queue_pkt.retries += 1
			queue_pkt.nexthop = nexthop
			self.arpqueue.put(queue_pkt)

	def send_enqueued_packets(self):
		'''
		() -> ()

		This method is periodically called in the main method
		to check the packets in the ARP queue waiting for ARP 
		replies.

		If any packet's next hop sent an ARP reply,
		this will send the packet along its way.

		If not, it will check if it has been 1 second since the
		last ARP reply for the next hop, and if it has, send
		another ARP request unless 5 requests have already been
		sent. In that case, the packet will be dropped.
		'''
		for i in range(self.arpqueue.qsize()):
			curr_pkt = self.arpqueue.get()
			# check cache
			if curr_pkt.nexthop not in self.arpcache:
				# need to check time of last ARP request
				if time.time() - curr_pkt.last_request > 1:
					# ARP again
					curr_pkt.retries += 1
					if not curr_pkt.is_dead():
						arppacket = self.create_arp_req(curr_pkt.interface_tosend,
							curr_pkt.nexthop)
						self.net.send_packet(curr_pkt.interface_tosend.name, arppacket)
						senttime = time.time()
						curr_pkt.update_rqst_time(senttime)
						self.arpqueue.put(curr_pkt)
					else:
						log_debug('Too many ARP requests, dropping packet: {}'
							.format(str(curr_pkt.packet)))
				else:	# put it back if it hasn't been a second
					self.arpqueue.put(curr_pkt)
			else:	# got ARP reply
				eth = curr_pkt.packet[curr_pkt.get_header_index(Ethernet)]
				eth.dst = self.arpcache[curr_pkt.nexthop]
				self.net.send_packet(curr_pkt.interface_tosend.name, 
					curr_pkt.packet)

	def create_arp_req(self, intf, targetip):
		'''
		(Interface, IPv4Address) -> (Packet)

		Creates an ARP request using the interface
		and the target IP address given.
		'''
		ether = Ethernet()
		ether.src = intf.ethaddr
		ether.dst = 'ff:ff:ff:ff:ff:ff'
		ether.ethertype = EtherType.ARP
		arp_req = Arp()
		arp_req.operation = ArpOperation.Request
		arp_req.senderhwaddr = intf.ethaddr
		arp_req.senderprotoaddr = intf.ipaddr
		arp_req.targethwaddr = 'ff:ff:ff:ff:ff:ff'
		arp_req.targetprotoaddr = targetip
		arppacket = ether + arp_req

		return arppacket

	def create_icmp_reply(self, ipv4hdr, icmphdr):
		'''
		(IPv4) -> Packet

		Creates an ICMP reply based on the header given.
		'''
		
		icmp = ICMP()


		return None


	def router_main(self):    
		'''
		() -> ()

		Main method for router; we stay in a loop in this method, receiving
		packets until the end of time.
		'''
		while True:
			gotpkt = True
			try:
				dev_name, pkt = self.net.recv_packet(timeout=1.0)
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
				icmp = pkt.get_header(ICMP)
				dev = self.net.interface_by_name(dev_name)
				if arp is not None:		# has ARP header
					if arp.targetprotoaddr == dev.ipaddr:
						if arp.targethwaddr == 'ff:ff:ff:ff:ff:ff':	# need to reply
							arp_reply = create_ip_arp_reply(dev.ethaddr,
															arp.senderhwaddr,
															dev.ipaddr,
															arp.senderprotoaddr)
							self.net.send_packet(dev_name, arp_reply)
						else: # got reply
							self.arpcache[arp.senderprotoaddr] = arp.senderhwaddr
							self.send_enqueued_packets()
					else:
						log_info("ARP request not for us, dropping: {}".format(str(pkt)))
				elif ipv4 is not None:	# has IPv4 header
					intf, index, nexthop = self.fwdtable_lookup(ipv4)
					if index != -1 and index != -2:	# has a match
						self.ready_packet(intf, pkt, nexthop)
						self.send_enqueued_packets()
					elif index == -1:	# no match
						log_info("No match in fwding table, dropping: {}".format(str(pkt)))
					else:	# index == -2, our packet; check ICMP request
						log_info("Packet for us: {}".format(str(pkt)))
						if icmp is not None:	# has ICMP header
							if icmp.icmptype == ICMPType.EchoRequest:	# is echo request
								icmp_reply = self.create_icmp_reply(ipv4, icmp)
								intf, index, nexthop = self.fwdtable_lookup(icmp_reply.get_header(IPv4))
								self.ready_packet(intf, icmp_reply, nexthop)

			self.send_enqueued_packets()

class ARPQueuePacket(object):
	'''
	A class that represents a packet waiting in the
	ARP queue.

	Contains information about number of retries,
	time of last ARP request, which interface to send
	once gets ARP reply, and the next hop it should
	be sent to.
	'''
	def __init__(self, pkt, intf):
		'''
		Initializes the queue packet, encapsulating
		the original packet.
		'''
		self.packet = pkt
		self.retries = 0
		self.last_request = time.time()
		self.interface_tosend = intf
		self.nexthop = IPv4Address(0)

	def is_dead(self):
		'''
		() -> (bool)

		Returns true if too many retries (more than 5)
		and false otherwise.
		'''
		return self.retries > 5

	def update_rqst_time(self, time):
		'''
		(long) -> ()

		Updates the last ARP request time.
		'''
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
