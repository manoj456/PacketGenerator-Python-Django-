import sys
from scapy.all import *

pkt=Ether()/IP()/ICMP()/"xxx"

if pkt:
	sendp(pkt)

