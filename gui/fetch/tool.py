'''
tool.py --
	General Information
	File owner : Manoj Tammali
	Description : Backend python file using scapy internally 
		      to modify pcaps by picking up from repository
'''
import sys
from scapy.all import *
import os
from scapy.error import Scapy_Exception

#Function to modify Ether pcap file from repository and provide it to user 
def fun1(sourceip, sourcemac, destip, destmac):
	i=0
	j=0
	print 'Hello i was here'
	array=rdpcap('fetch/repository/Ether.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum
			if destip:         
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:   
                        	array[j][Ether].dst=destmac
                j=j+1
	#providing pcap back to the user
	wrpcap('fetch/static/Ether.cap',array)
	filepath = 'Ether.cap'
	return filepath
#Function to modify Ether+UDP pcap file from repository and provide it to user
def fun2(sourceip, sourcemac, destip, destmac,srcport,dstport):

	
	i=0
	j=0
	k=0
	array=rdpcap('fetch/repository/Ether+UDP.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum
			if destip:         
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1

	while k < len(array):
                if array[k].haslayer(UDP):
                        if srcport:
                                array[k][UDP].sport=int(srcport)
                        if dstport:
                                array[k][UDP].dport=int(dstport)
                k=k+1
	#providing pcap back to the user
	wrpcap('fetch/static/Ether+UDP.cap',array)
	filepath = 'Ether+UDP.cap'
	return filepath
#Function to modify Ether+TCP pcap file from repository and provide it to user
def fun3(sourceip,sourcemac,destip,destmac,srcport,dstport):

	i=0
	j=0
	k=0
	array=rdpcap('fetch/repository/Ether+TCP.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum
			if destip:
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1

	while k < len(array):
                if array[k].haslayer(TCP):
                        if srcport:
                                array[k][TCP].sport=int(srcport)
                        if dstport:
                                array[k][TCP].dport=int(dstport)
                k=k+1
	#providing pcap back to the user
	wrpcap('fetch/static/Ether+TCP.cap',array)
	filepath = 'Ether+TCP.cap'
	return filepath

#Function to modify Ether+ICMP pcap file from repository and provide it to user
def fun4(sourceip,sourcemac,destip,destmac):

	i=0
	j=0
	array=rdpcap('fetch/repository/Ether+ICMP.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum 
			if destip:        
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1
	#providing pcap back to the user
	wrpcap('fetch/static/Ether+ICMP.cap',array)
	filepath = 'Ether+ICMP.cap'
	return filepath

#Function to modify other_security pcap file from repository and provide it to user
def fun5(sourceip,sourcemac,destip,destmac):

	i=0
	j=0
	
	#Reading pcap and modifying fields based on user input
	array=rdpcap('fetch/repository/other_security.cap')
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum 
			if destip:        
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:	
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1
	#providing pcap back to the user
	wrpcap('fetch/static/other_security.cap',array)
	filepath = 'other_security.cap'
	return filepath

#Function to modify TCP pcap file from repository and provide it to user
def fun6(sourceip,sourcemac,destip,destmac,srcport,dstport):

	i=0
	j=0
	k=0
	array=rdpcap('fetch/repository/TCP.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum
			if destip:         
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1
        while k < len(array):
                if array[k].haslayer(TCP):
                        if srcport:
                                array[k][TCP].sport=int(srcport)
                        if dstport:
                                array[k][TCP].dport=int(dstport)
                k=k+1
	#providing pcap back to the user
	wrpcap('fetch/static/TCP.cap',array)
	filepath = 'TCP.cap'
	return filepath
#Function to modify UDP pcap file from repository and provide it to user
def fun7(sourceip,sourcemac,destip,destmac,srcport,dstport):

	i=0
	j=0
	k=0
	array=rdpcap('fetch/repository/UDP.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum  
			if destip:       
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1

        while k < len(array):
                if array[k].haslayer(UDP):
                        if srcport:
                                array[k][UDP].sport=int(srcport)
                        if dstport:
                                array[k][UDP].dport=int(dstport)
                k=k+1
	#providing pcap back to the user
	wrpcap('fetch/static/UDP.cap',array)
	filepath = 'UDP.cap'
	return filepath
#Function to modify ICMP pcap file from repository and provide it to user
def fun8(sourceip,sourcemac,destip,destmac):

	i=0
	j=0
	array=rdpcap('fetch/repository/ICMP.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum 
			if destip:        
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1
	#providing pcap back to the user
	wrpcap('fetch/static/ICMP.cap',array)
	filepath = 'ICMP.cap'
	return filepath
#Function to modify Ether+IP pcap file from repository and provide it to user
def fun9(sourceip,sourcemac,destip,destmac):

	i=0
	j=0
	array=rdpcap('fetch/repository/Ether+IP.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum
			if destip:         
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1
	#providing pcap back to the user
	wrpcap('fetch/static/Ether+IP.cap',array)
	filepath = 'Ether+IP.cap'
	return filepath
#Function to modify Ether+IP+ICMP pcap file from repository and provide it to user
def fun10(sourceip,sourcemac,destip,destmac):

	i=0
	j=0
	array=rdpcap('fetch/repository/Ether+IP+ICMP.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum  
			if destip:       
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1
	#providing pcap back to the user
	wrpcap('fetch/static/Ether+IP+ICMP.cap',array)
	filepath = 'Ether+IP+ICMP.cap'
	return filepath

#Function to modify Ether+IP+TCP pcap file from repository and provide it to user
def fun11(sourceip,sourcemac,destip,destmac,srcport,dstport):

	i=0
	j=0
	k=0
	array=rdpcap('fetch/repository/Ether+IP+TCP.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum
			if destip:         
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1
        while k < len(array):
                if array[k].haslayer(TCP):
                        if srcport:
                                array[k][TCP].sport=int(srcport)
                        if dstport:
                                array[k][TCP].dport=int(dstport)
                k=k+1
	#providing pcap back to the user
	wrpcap('fetch/static/Ether+IP+TCP.cap',array)
	filepath = 'Ether+IP+TCP.cap'
	return filepath

#Function to modify Ether+IP+UDP pcap file from repository and provide it to user
def fun12(sourceip,sourcemac,destip,destmac,srcport,dstport):

	i=0
	j=0
	k=0
	array=rdpcap('fetch/repository/Ether+IP+UDP.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum 
			if destip:        
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1
        while k < len(array):
                if array[k].haslayer(UDP):
                        if srcport:
                                array[k][UDP].sport=int(srcport)
                        if dstport:
                                array[k][UDP].dport=int(dstport)
                k=k+1
	#providing pcap back to the user
	wrpcap('fetch/static/Ether+IP+UDP.cap',array)
	filepath = 'Ether+IP+UDP.cap'
	return filepath

#Function to modify IP pcap file from repository and provide it to user
def fun13(sourceip,sourcemac,destip,destmac):

	i=0
	j=0
	array=rdpcap('fetch/repository/IP.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum 
			if destip:        
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1
	#providing pcap back to the user
	wrpcap('fetch/static/IP.cap',array)
	filepath = 'IP.cap'
	return filepath
#Function to modify IP+TCP pcap file from repository and provide it to user
def fun14(sourceip,sourcemac,destip,destmac,srcport,dstport):

	i=0
	j=0
	k=0
	array=rdpcap('fetch/repository/IP+TCP.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum
			if destip:         
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1
        while k < len(array):
                if array[k].haslayer(TCP):
                        if srcport:
                                array[k][TCP].sport=int(srcport)
                        if dstport:
                                array[k][TCP].dport=int(dstport)
                k=k+1

	#providing pcap back to the user
	wrpcap('fetch/static/IP+TCP.cap',array)
	filepath = 'IP+TCP.cap'
	return filepath
#Function to modify IP+UDP pcap file from repository and provide it to user
def fun15(sourceip,sourcemac,destip,destmac,srcport,dstport):

	i=0
	j=0
	k=0
	array=rdpcap('fetch/repository/IP+UDP.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum
			if destip:         
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1
        while k < len(array):
                if array[k].haslayer(UDP):
                        if srcport:
                                array[k][UDP].sport=int(srcport)
                        if dstport:
                                array[k][UDP].dport=int(dstport)
                k=k+1
	#providing pcap back to the user
	wrpcap('fetch/static/IP+UDP.cap',array)
	filepath = 'IP+UDP.cap'
	return filepath

#Function to modify IP+ICMP pcap file from repository and provide it to user
def fun16(sourceip,sourcemac,destip,destmac):

	i=0
	j=0
	array=rdpcap('fetch/repository/IP+ICMP.cap')
	#Reading pcap and modifying fields based on user input
	while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum  
			if destip:       
                        	array[i][IP].dst=destip
			if sourceip:
                        	array[i][IP].src=sourceip
                i=i+1

	while j < len(array):
                if array[j].haslayer(Ether):
			if sourcemac:
                        	array[j][Ether].src=sourcemac
			if destmac:
                        	array[j][Ether].dst=destmac
                j=j+1
	#providing pcap back to the user
	wrpcap('fetch/static/IP+ICMP.cap',array)
	filepath = 'IP+ICMP.cap'
	return filepath

#Function to modify IPoptions pcap file from repository and provide it to user
def fun17(sourceip,sourcemac,destip,destmac):

        i=0
        j=0
        array=rdpcap('fetch/repository/Ipoptions.cap')
	#Reading pcap and modifying fields based on user input
        while i < len(array):
                if array[i].haslayer(IP):
                        del array[i][IP].chksum
                        if destip:
                                array[i][IP].dst=destip
                        if sourceip:
                                array[i][IP].src=sourceip
                i=i+1

        while j < len(array):
                if array[j].haslayer(Ether):
                        if sourcemac:
                                array[j][Ether].src=sourcemac
                        if destmac:
                                array[j][Ether].dst=destmac
                j=j+1
	#providing pcap back to the user
        wrpcap('fetch/static/Ipoptions.cap',array)
        filepath = 'Ipoptions.cap'
        return filepath


#Function to modify arpcachepoison pcap file from repository and provide it to user

def fun18(sourceip,sourcemac,destip,destmac):

        i=0
       
        array=rdpcap('fetch/repository/arpcachepoison.cap')
	#Reading pcap and modifying fields based on user input
        while i < len(array):
                
                if destip:
	           	array[i][ARP].pdst=destip
                if sourceip:
                        array[i][ARP].psrc=sourceip
		if sourcemac:
			array[i][ARP].hwsrc=sourcemac
			array[i][Ether].src=sourcemac
		if destmac:
			array[i][ARP].hwdst=destmac
			array[i][Ether].dst=destmac
                i=i+1
	#providing pcap back to the user
        wrpcap('fetch/static/arpcachepoison.cap',array)
        filepath = 'arpcachepoison.cap'
        return filepath




	       


