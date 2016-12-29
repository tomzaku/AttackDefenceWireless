from scapy.all import *
import sys
import os
import signal
ap_list = []

def usage():
	if len(sys.argv) < 3:
		print
		print "Usage:"
		print "\twifi-scanner.py -i <interface>"
		print
		sys.exit(1)
def init_process ():
	global ssid_list
	ssid_list = {}
	global s
	s = conf.L2socket(iface=newiface)
def signal_handler(signal, frame):
	print('\n=================')
	print('Execution aborted')
	print('=================')
	os.system("kill -9 " + str(os.getpid()))
	sys.exit(1)

def PacketHandler(pkt) :
	# pkt.show()
    if pkt.haslayer(Dot11) :
        if pkt.type == 0 and pkt.subtype == 8 :
            if pkt.addr2 not in ap_list :
				ap_list.append(pkt.addr2)
				print "BEACON: AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)
	if pkt.haslayer(Dot11ProbeReq):
		if pkt.addr2 not in ap_list:
				# ap_list.append(pkt.addr2)
				print "PROBE:SUB_TYPE:"+str(pkt.subtype) +" AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)

def setup_monitor(iface):
	print "Setting up sniff options..."
	os.system('ifconfig ' + iface + ' down')
	try:
		os.system('iwconfig ' + iface + ' mode monitor')
	except:
		print "Failed to setup monitor mode"
		sys.exit(1)
	os.system('ifconfig ' + iface + ' up')
	return iface

if __name__ == "__main__":
	signal.signal(signal.SIGINT, signal_handler)
	usage()
	parameters ={sys.argv[1]:sys.argv[2]}
	if "mon" not in str(parameters["-i"]):
		newiface = setup_monitor(parameters["-i"])
	else:
		newiface = str(parameters["-i"])
	init_process()
	print "Sniffing on interface " + str(newiface) + "...\n"
	sniff(iface=newiface, prn=PacketHandler, store=0)
