from scapy.all import *

class DNSHandler(file_path):

	def summary():
	for packet in self.pcap :
		if packet.haslayer(DNS):
			packet.show()

	def __init__(self)
	self.pcap = rdpcap(file_path)
	