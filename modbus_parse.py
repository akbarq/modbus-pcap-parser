#Author: Akbar Qureshi
#Extracts Source Ip, Destination IP, Modbus Port, Modbus Unit ID and Modbus Fucntion Code from pcap file

import dpkt
import sys
from socket import inet_ntoa
import datetime

class ModBusTCP(dpkt.Packet):
    __hdr__ = (('id', 'H', 0),
               ('proto', 'H', 0),
               ('len', 'H', 0),
               ('ui', 'B', 0),
               ('fc', 'B', 0))

if len(sys.argv) < 2:
    sys.exit('Usage: %s pcap-file' % sys.argv[0])

pcap_file = open(sys.argv[1], 'rb')
	
pcap = dpkt.pcap.Reader(pcap_file)

for ts, buf in pcap:
	eth = dpkt.ethernet.Ethernet(buf)
    	if type(eth.data) != dpkt.ip.IP:
        	continue
    	ip = eth.data
    	if type(ip.data) != dpkt.tcp.TCP:
        	continue
    	tcp = ip.data
	if not (len(tcp.data) > 0 and (tcp.sport == 502 or  tcp.dport == 502)):
		continue


	if (tcp.dport==502) and len(tcp.data)>0:
		try:
			print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(ts))
			print 'Src IP:', inet_ntoa(ip.src)
			print 'Dst IP:', inet_ntoa(ip.dst)
			print 'Dst Port:', tcp.dport
			modtcp = ModBusTCP(tcp.data)
			if modtcp.fc < 255 and modtcp.proto == 0:
				print 'Unit ID:', modtcp.ui, '\nFunction Code:', modtcp.fc
				print ''
		except dpkt.dpkt.NeedData:
			continue
