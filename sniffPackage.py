from scapy.all import *
import sys
import os
import collections

ap_list = []
stations=[]
stationSrcs=[]
stationDecs=[]
stationSrcTimes={}
stationDecTimes={}

def signal_handler(signal, frame):
	print('\n=================')
	print('Execution aborted')
	print('=================')
	os.system("kill -9 " + str(os.getpid()))
	sys.exit(1)

def PacketHandler(pkt):
    # global stations
    if pkt.haslayer(IP):
        pckt_src=pkt[IP].src
        pckt_dst=pkt[IP].dst
        pckt_ttl=pkt[IP].ttl
        stationSrcs.append(pckt_src)
        stationDecs.append(pckt_dst)
        # if pckt_src not in stations:
        #     stations.append(pckt_src)
        # print "Packet: %s is going to %s and has ttl value %s" % (pckt_src,pckt_dst,pckt_ttl)
        stationSrcTimes= collections.Counter(stationSrcs)
        stationDecTimes= collections.Counter(stationDecs)
        print "SRC=> "+ str(stationSrcTimes)
        print "DEC=> "+ str(stationDecTimes)
if __name__ == "__main__":
	# sniff(prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"))
	sniff(prn=PacketHandler)
