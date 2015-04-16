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

	def fwdtable_lookup(self, ipv4, src_lookup):
		'''
		(IPv4) -> (str, int, str)

		Looks up a certain IPv4 address in the forwarding table,
		returning the entry in the table.

		The keys to the table are interfaces and the integer
		specifies which item to look for in the list of network prefixes
		associated with the interface in question.
		'''
		dst_ipaddr = IPv4Address(ipv4.srcip) if src_lookup else IPv4Address(ipv4.dstip)
		most_precise_prefix = (None, None, -1, None)


		for intf_name in self.fwdtable.keys():						# every interface in forwarding table
			intf = self.net.interface_by_name(intf_name)
			if intf.ipaddr == dst_ipaddr:							# ourselves
				return (str(dst_ipaddr), -2, str(dst_ipaddr))		# -2 for ourselves
			for i in range(len(self.fwdtable[intf_name])):			# every prefix asc.'d with the interface
				prefixnet, nexthop = self.fwdtable[intf_name][i]
				if dst_ipaddr in prefixnet:
					if most_precise_prefix[0] == None:
						most_precise_prefix = (prefixnet, intf_name, i, nexthop)
					elif most_precise_prefix[0].prefixlen < prefixnet.prefixlen:
						most_precise_prefix = (prefixnet, intf_name, i, nexthop)

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

		ipv4 = pkt.get_header(IPv4)
		ipv4.ttl -= 1
		if ipv4.ttl == 0:
			self.report_error(pkt, 1)
			return

		eth = pkt.get_header(Ethernet)
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
					if curr_pkt.retries < 5:
						arppacket = self.create_arp_req(curr_pkt.interface_tosend,
							curr_pkt.nexthop)
						self.net.send_packet(curr_pkt.interface_tosend.name, arppacket)
						senttime = time.time()
						curr_pkt.update_rqst_time(senttime)
						self.arpqueue.put(curr_pkt)
					else:
						log_debug('Too many ARP requests, dropping packet: {}'
							.format(str(curr_pkt.packet)))
						self.report_error(curr_pkt.packet, 2)
				else:	# put it back if it hasn't been a second
					self.arpqueue.put(curr_pkt)
			else:	# got ARP reply
				eth = curr_pkt.packet.get_header(Ethernet)
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


	def create_icmp_reply(self, echo_request):
		'''
		(Packet) -> Packet

		Creates an ICMP reply based on the echo request given.

		Precondition: request has ipv4 and icmp headers
		'''
		
		icmp_req_hdr = echo_request.get_header(ICMP)
		ipv4hdr = echo_request.get_header(IPv4)

		icmp = ICMP()
		icmp.icmpcode = 0
		icmp.icmptype = ICMPType.EchoReply
		icmp.icmpdata.identifier = icmp_req_hdr.icmpdata.identifier
		icmp.icmpdata.sequence = icmp_req_hdr.icmpdata.sequence
		icmp.icmpdata.data = icmp_req_hdr.icmpdata.data

		intf_name, match, nexthop = self.fwdtable_lookup(ipv4hdr, True)
		intf = self.net.interface_by_name(intf_name)

		ip = IPv4()
		ip.dstip = ipv4hdr.srcip
		ip.srcip = ipv4hdr.dstip
		ip.ttl = 65

		eth = Ethernet()
		eth.ethertype = EtherType.IPv4
		eth.src = intf.ethaddr

		icmp_reply = eth + ip + icmp

		return icmp_reply, intf_name, nexthop


	def report_error(self, pkt, error_type):
		'''
		Sends error message back to the host 
		through the interface through which the error-inducing
		ipv4 packet is received 
		'''

		i = pkt.get_header_index(Ethernet)
		del pkt[i]

		ipv4 = pkt.get_header(IPv4)

		icmp = ICMP()

		if error_type == 0:			# dst unreachable
			icmp.icmptype = ICMPType.DestinationUnreachable
			icmp.icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].NetworkUnreachable

		elif error_type == 1: 		# timeexceeded
			icmp.icmptype = ICMPType.TimeExceeded
			icmp.icmpcode = ICMPTypeCodeMap[ICMPType.TimeExceeded].TTLExpired # TTLExpired: 11

		elif error_type == 2:		# arp failure
			icmp.icmptype = ICMPType.DestinationUnreachable
			icmp.icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].HostUnreachable # HostUnreachable: 1

		else:						# dst port unreachable
			icmp.icmptype = ICMPType.DestinationUnreachable
			icmp.icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].PortUnreachable # PortUnreachable: 3

		icmp.icmpdata.data = pkt.to_bytes()[:28]

		intf_name, match, nexthop = self.fwdtable_lookup(ipv4, True)
		intf = self.net.interface_by_name(intf_name)

		ip = IPv4()
		ip.protocol = IPProtocol.ICMP
		ip.dstip = ipv4.srcip
		ip.srcip = intf.ipaddr
		ip.ttl = 65

		eth = Ethernet()
		eth.ethertype = EtherType.IPv4
		eth.src = intf.ethaddr

		err_pkt = eth + ip + icmp
		self.ready_packet(intf_name, err_pkt, nexthop)


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
						if arp.operation == ArpOperation.Request:
							arp_reply = create_ip_arp_reply(dev.ethaddr,
															arp.senderhwaddr,
															dev.ipaddr,
															arp.senderprotoaddr)
							self.net.send_packet(dev_name, arp_reply)
						else:
							self.arpcache[arp.senderprotoaddr] = arp.senderhwaddr
							self.send_enqueued_packets()
					else:
						log_info("ARP request not for us, dropping: {}".format(str(pkt)))
				elif ipv4 is not None:	# has IPv4 header
					intf, match, nexthop = self.fwdtable_lookup(ipv4, False)

					if match != -1 and match != -2:	# has a match
						self.ready_packet(intf, pkt, nexthop)
						self.send_enqueued_packets()
						
					elif match == -1:	# no match
						self.report_error(pkt, 0)  # destination network unreachable error 

					else:	# match == -2, our packet; check ICMP request
						if icmp is not None:	# has ICMP header
							if icmp.icmptype == ICMPType.EchoRequest:	# is echo request
								icmp_reply, intf_name, nexthop = self.create_icmp_reply(pkt)
								self.ready_packet(intf_name, icmp_reply, nexthop)
						else:	# not an ICMP echo request, destination port unreachable error
							self.report_error(pkt, 3) 
				else:
					log_info("Got packet that is not ARP or IPv4, dropping: {}".format(str(pkt)))
					
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
