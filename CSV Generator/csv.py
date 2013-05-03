from scapy.all import *
from collections import Counter
import os
#Send path to file to scanned
def ext(f):
    pcap = rdpcap(f)
    l = []
    #taking one packet at a time and dissecting it's IP layer
    for pkt in pcap:
        ip = pkt.getlayer(IP)
        l.append((ip.src,ip.dst))
    f = Counter(l)
    csv = open("data.csv","w")
    csv.write("source,target,value" + os.linesep)
    for key in f.keys():
        #writing file into .txt in source,target,value
        # value is the number of connection between two ip's
        data = ",".join(map(str,[key[0],key[1],f[key]]))
        csv.write(data + os.linesep)
    csv.close()
        
