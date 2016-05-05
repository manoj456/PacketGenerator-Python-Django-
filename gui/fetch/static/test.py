import sys
from scapy.all import *

pkt=rdpcap('TCP.cap')

if pkt:
	wireshark(pkt)
