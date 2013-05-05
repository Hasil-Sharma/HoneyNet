from scapy.all import *
from detector import *
class DNSHandler():
	def __init__(self,file_path):
		self.pcap = rdpcap(file_path)

	def DNSAnomalyDetector(self):
		packetdictionary = dict()
		for packet in self.pcap :
			if packet.haslayer(DNS):
				data = (packet[IP].src, packet[IP].dst, packet[IP].sport, packet[IP].dport)
				ID = packet[DNS].id
				if packet.haslayer(DNS):
					dns = packet.getlayer(DNS)
					if dns.qr == 0:
						packetdictionary[(data,ID)] = packet
					else:
						if (data,ID) not in packetdictionary.keys():
							print "Anomaly Detected: Response without A Request"
							print packet.summary()
					malformed = malformedpacket(packet)


a = DNSHandler("dns-remoteshell.pcap")

a.DNSAnomalyDetector()
