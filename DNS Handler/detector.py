from scapy.all import *
import sys
DNSPORT = [53,]    
# I have done this coding just to show concept work , other checkers viz. size of check can also be added
def malformedpacket(pkt):
    global DNSPORT
    try:
        ip_layer = pkt.getlayer(IP)
        dport = ip_layer.dport
        sport = ip_layer.sport
        #size = sys.getsizeof(pkt[DNS]) # Gives size of DNS Packet in bytes len() doesn't provide answer in bytes
        if (dport in DNSPORT) or (sport in DNSPORT):
            if pkt.haslayer(DNS):
                if pkt[DNS].tc:
                    print "Anomaly detected: Packet exceeds 512 bytes"
                    print pkt.show()
                if pkt[DNS].rcode != 0:
                    print "Anomaly detected: Errors in the DNS"
                    print pkt.show()
            else:
                print "Anomaly detected: Packet doesn't contain valid DNS but is using it's port"
                print pkt.show()
        else:
            print "Anomaly detected: Packet is using a non-standard port"
            print pkt.show()
        return True
    except:
        return False
