from scapy.all import *

class DNSHandler():

	def summary(self):
	    for packet in self.pcap :
		    if packet.haslayer(DNS):
			    packet.show()

	def __init__(self,file_path):
	    self.pcap = rdpcap(file_path)
	
