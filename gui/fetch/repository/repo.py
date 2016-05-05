'''
	repo.py --
		General Information
		File Owner : Manoj Tammali
		Description : Repository of pcaps generated using this 
			      python file which uses scapy internally

'''
import sys
from scapy.all import *
#Malformed packets with only ICMP layer malformed
'''
Packets of this combination include 

	Ether()/IP() - Default values are taken for these layers

	ICMP() - Fields manipulated all possible ways for this layer

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''
ic1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=0,code=[0,1,10,15])/"xxx"

ic2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=[1,2,6,7,19,(20,29),(31,255)],code=[0,10,15])/"xxx"

ic3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=5,code=[0,2,4,10,15])/"xxx"

ic4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=11,code=[0,2,10,15])/"xxx"

ic5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=12,code=[0,1,3,12,15])/"xxx"

ic6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=[(8,10),(13,18),30],code=[0,1,5,10,15])/"xxx"

ic7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(chksum=[0x0000,0xdabc,0xffff])/"xxx"

ic8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/fuzz(ICMP())/"xxx"

ic9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(id=[0,65535],seq=[0,65535])/"xxx"

ic10=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(chksum=[0x0000,0xdbcc,0xffff])/""



iclist=[p for p in ic1]+[p for p in ic2]+[p for p in ic3]+[p for p in ic4]+[p for p in ic5]+[p for p in ic6]+[p for p in ic7]+[p for p in ic8]+[p for p in ic9]+[p for p in ic10]

if iclist:
	#print "ICMP packets count=",len(iclist)
	wrpcap('ICMP.cap',iclist)
#IP with ICMP as payload
'''
Packets of this combination include 

	Ether() - Default field values taken for this layer

	IP()/ICMP() - Fields manipulated all possible ways for these layers

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''

icm1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=(20,27))/ICMP()/"xxx"

icm2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",proto=(0,255))/ICMP()/"xxx"

icm3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[6,7])/ICMP()/"xxx"

icm4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",chksum=[0x0,0xdbac,0xffff])/ICMP()/"xxx"

icm5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",chksum=[0x0,0xdbbc,0xffff])/ICMP(chksum=[0x00,0xcdba,0xffff])/"xxx"

icm6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=(0,15))/ICMP()/"xxx"

icm7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=[1,10,15,19,28,65535])/ICMP()/"xxx"

icm8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=(0,15),len=[10,15,19,(20,27),28,65535])/ICMP()/"xxx"

icm9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",flags=[(0,4),6,7])/ICMP()/"xxx"

icm10=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",frag=[0,48,8191])/ICMP()/"xxx"

icm11=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ttl=[0,255])/ICMP()/"xxx"

icm12=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",tos=[0,255])/ICMP()/"xxx"

icm13=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",version=(0,15),proto=1)/ICMP()/"xxx"

icm14=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=(0,15),len=(10,25),chksum=[0xdcca,0xffff,0x00])/ICMP()/"xxx"

icm15=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP()/"xxx"

icm16=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=23)/ICMP()/"xxx"

icm17=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=27)/ICMP()/"xxx"

icm18=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=28)/ICMP()/"xxx"

icm19=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",proto=[6,17])/ICMP()/"xxx"

icm20=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=2,version=3)/ICMP()/"xxx"

icmlist=[p for p in icm1]+[p for p in icm2]+[p for p in icm3]+[p for p in icm4]+[p for p in icm5]+[p for p in icm6]+[p for p in icm7]+[p for p in icm8]+[p for p in icm9]+[p for p in icm10]+[p for p in icm11]+[p for p in icm12]+[p for p in icm13]+[p for p in icm14]+[p for p in icm15]+[p for p in icm16]+[p for p in icm17]+[p for p in icm18]+[p for p in icm19]+[p for p in icm20]

if icmlist:
	#print "IP+ICMP packets count=",len(icmlist)
	wrpcap('IP+ICMP.cap',icmlist)

#UDP List
'''
Packets of this combination include 

        Ether()/IP() - Default field values taken for these layers

        UDP() - Fields manipulated all possible ways for this layer

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''
u1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/fuzz(UDP())/"xxx"

u2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/fuzz(UDP()/NTP(version=4))/"xxx"

u3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826)/"xxx"

u4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826,len=(0,7))/"xxx"

u5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826,len=[8,9,10,11,(13,17),20,65535])/"xxx"

u6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826,chksum=[0x00,0xdbac,0xffff])/"xxx"

u7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=[8826,9826],dport=[9826,8826])/"xxx"

u8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826,len=[(0,7),8,9,10,11,(13,17),20,65535],chksum=[0x00,0xdbac,0xffff])/"xxx"

u9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826)/("x"*10)

u10=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826,len=[(0,7),8,9,10,11,20,65535])/""

u11=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826,len=[(0,7),8,9,10,11,(13,17),20,65535])/"xxx"

u12=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826)/"xxx"

u13=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826,len=7)/"xxx"

u14=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826,len=17)/"xxx"

ulist=[p for p in u1]+[p for p in u2]+[p for p in u3]+[p for p in u4]+[p for p in u5]+[p for p in u6]+[p for p in u7]+[p for p in u8]+[p for p in u9]+[p for p in u10]+[p for p in u11]+[p for p in u12]+[p for p in u13]+[p for p in u14]

if ulist:
	#print "UDP Len=",len(ulist)
	wrpcap('UDP.cap',ulist)

#IP and UDP List

'''
Packets of this combination include 

        Ether() - Default field values taken for this layer

        IP()/UDP() - Fields manipulated all possible ways for these layers

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''

ud1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=(20,27))/UDP(sport=8826,dport=9826)/"xxx"

ud2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",proto=(0,255))/UDP(sport=8826,dport=9826)/"xxx"

ud3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",flags=[(0,4),6,7])/UDP(sport=8826,dport=9826)/("x"*224)

ud4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=28)/UDP(sport=8826,dport=9826,len=[0,7,9,10,20])/"xxx"

ud5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=28)/UDP(sport=8826,dport=9826,chksum=[0x00,0xffff,0xdbac])/"xxx"

ud6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[2,6,7,11,20])/UDP(sport=8826,dport=9826)/"xxx"

ud7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",flags="MF")/UDP(sport=8826,dport=9826)/("X"*224)

ud8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",version=(0,15),proto=17)/UDP(sport=8826,dport=9826)/"xxx"

ud9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=[20,28,31,40])/UDP(sport=8826,dport=9826)/"xxx"

ud10=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=(0,15))/UDP(sport=8826,dport=9826)/"xxx"

ud11=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",chksum=[0x0,0xdbac,0xffff])/UDP(sport=8826,dport=9826)/"xxx"

ud12=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",chksum=[0x0,0xdbbc,0xffff])/UDP(sport=8826,dport=9826,chksum=[0x00,0xcdba,0xffff])/"xxx"

ud13=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=(0,15),len=(20,25),chksum=[0xdcca,0xffff,0x00])/UDP(sport=8826,dport=9826)/"xxx"

ud14=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826)/"xxx"

ud15=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",frag=[0,48,8191])/UDP(sport=8826,dport=9826)/("x"*224)

ud16=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=27)/UDP(sport=8826,dport=9826)/"xxx"

ud17=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=[23,35])/UDP(sport=8826,dport=9826)/"xxx"

ud18=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",proto=6)/UDP(sport=8826,dport=9826)/"xxx"


udlist=[p for p in ud1]+[p for p in ud2]+[p for p in ud3]+[p for p in ud4]+[p for p in ud5]+[p for p in ud6]+[p for p in ud7]+[p for p in ud8]+[p for p in ud9]+[p for p in ud10]+[p for p in ud11]+[p for p in ud12]+[p for p in ud13]+[p for p in ud14]+[p for p in ud15]+[p for p in ud16]+[p for p in ud17]+[p for p in ud18]

if udlist:
	#print "IP+UDP packets count=", len(udlist)
	wrpcap('IP+UDP.cap',udlist)

#TCP only
'''
Packets of this combination include 

        Ether()/IP() - Default field values taken for this layer

        TCP() - Fields manipulated all possible ways for these layers

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''

t1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,dataofs=[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10])/"xxx"

t2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/fuzz(TCP(sport=8826,dport=9826))/"xxx"

t3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826)/"xxx"

t4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,dataofs=(0,5))/"xxx"

t5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,chksum=[0x00,0xdbac,0xffff])/"xxx"

t6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,reserved=(1,7))/"xxx"

t7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,dataofs=[0,4,10,61])/"xxx"

t8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,chksum=[0x00,0xdbac,0xffff])/"xxx"

t9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,flags="A")/"xxx"

t10=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,flags=0x1DF,urgptr=[1,123])/"xxx"

t11=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,flags=0x1EF,ack=[1,123])/"xxx"

t12=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,flags=0x1FD,seq=[1,123])/"xxx"

t13=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,flags=0x1FF,seq=0,ack=123,urgptr=0)/"xxx"

t14=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,window=[0,8193])/"xxx"

t15=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,chksum=[0xbdca,0xffff,0x0000],dataofs=[0,4,5,10,61])/""

t16=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,flags="S")/"xxx"

t17=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,flags=0x2)/"xxx"

t18=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,seq=[0,345631],ack=[0,1,2321233])/"xxx"

t19=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,window=[0,8193])/"xxx"

t20=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826)/""

t21=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,dataofs=0x0)/""

tlist=[p for p in t1]+[p for p in t2]+[p for p in t3]+[p for p in t4]+[p for p in t5]+[p for p in t6]+[p for p in t7]+[p for p in t8]+[p for p in t9]+[p for p in t10]+[p for p in t11]+[p for p in t12]+[p for p in t13]+[p for p in t14]+[p for p in t15]+[p for p in t16]+[p for p in t17]+[p for p in t18]+[p for p in t19]+[p for p in t20]+[p for p in t21]

if tlist:
	#print "TCP packets count=",len(tlist)
	wrpcap('TCP.cap',tlist)

#IP and TCP
'''
Packets of this combination include 

        Ether() - Default field values taken for this layer

        IP()/TCP() - Fields manipulated all possible ways for these layers

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''

tcp1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=(20,50))/TCP(sport=8826,dport=9826)/"xxx"

tcp2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=39)/TCP(sport=8826,dport=9826)/"xxx"

tcp3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=40)/TCP(sport=8826,dport=9826,dataofs=10)/"xxx"

tcp4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",proto=(0,255))/TCP(sport=8826,dport=9826)/"xxx"

tcp5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[2,6,7,9])/TCP(sport=8826,dport=9826)/"xxx"

tcp6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=68)/TCP(sport=8826,dport=9826,dataofs=12)/"xxx"

tcp7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",chksum=[0x00,0xdbac,0xffff])/TCP(sport=8826,dport=9826,chksum=[0x00,0xdbac,0xffff])/"xxx"

tcp8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=(0,15))/TCP(sport=8826,dport=9826)/"xxx"

tcp9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=(0,15),len=[(20,27),28,65535])/TCP(sport=8826,dport=9826)/"xxx"

tcp10=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",flags=[(0,4),6,7])/TCP(sport=8826,dport=9826)/"xxx"

tcp11=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",frag=[0,48,8191])/TCP(sport=8826,dport=9826)/"xxx"

tcp12=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=(0,15),len=(20,25),chksum=[0xdcca,0xffff,0x00])/TCP(sport=8826,dport=9826)/"xxx"

tcp13=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",version=(0,15),proto=6)/TCP(sport=8826,dport=9826)/"xxx"

tcp14=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826)/"xxx"

tcp15=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=[20,25,30,35,40])/TCP(sport=8826,dport=9826)/"xxx"

tcp16=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=[41,50])/TCP(sport=8826,dport=9826)/"xxx"

tcp17=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=53)/TCP(sport=8826,dport=9826)/"xxx"

tcp18=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=40)/TCP(sport=8826,dport=9826,dataofs=40)/"xxx"

tcp19=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",proto=17)/TCP(sport=8826,dport=9826)/"xxx"

tcp20=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826)/"xxx"

tcplist=[p for p in tcp1]+[p for p in tcp2]+[p for p in tcp3]+[p for p in tcp4]+[p for p in tcp5]+[p for p in tcp6]+[p for p in tcp7]+[p for p in tcp8]+[p for p in tcp9]+[p for p in tcp10]+[p for p in tcp11]+[p for p in tcp12]+[p for p in tcp13]+[p for p in tcp14]+[p for p in tcp15]+[p for p in tcp16]+[p for p in tcp17]+[p for p in tcp18]+[p for p in tcp19]+[p for p in tcp20]

if tcplist:
	#print "IP+TCP packets count=",len(tcplist)
	wrpcap('IP+TCP.cap',tcplist)

#Attacks 
'''
Generated all possible combinations of known issue packets into an array and stored them in a pcap file  

'''

a1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826)/("x"*241)

a2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",id=42,flags="MF")/UDP()/("X"*10)/("x"*224)

a3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",id=42,flags=48)/("X"*116)/("x"*216)

a4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",id=42,flags="MF")/UDP()/("X"*223)

a5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,flags="S",options=[('Timestamp',(0,0))])/"xxx"

a6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/fuzz(TCP(sport=8826,dport=9826))/"xxx"

a7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/fuzz(ICMP())/"xxx"

a8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/fuzz(UDP())/"xxx"

a9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/fuzz(UDP()/NTP(version=4))/"xxx"

a10=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=2,version=3)/ICMP()/("x"*600)

alist=[p for p in a1]+[p for p in a2]+[p for p in a3]+[p for p in a4]+[p for p in a5]+[p for p in a6]+[p for p in a7]+[p for p in a8]+[p for p in a9]+[p for p in a10]


if alist:
	#print "Attacks packets count=",len(alist)
	wrpcap('other_security.cap',alist)

#Ether Layer
'''
Packets of this combination include 

        IP() - Default field values taken for this layer

        Ether() - Fields manipulated all possible ways for these layers

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''

e1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/"xxx"

e2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,(0x5DD,0x600),0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/"xxx"

e3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,(0x5DD,0x600),0x800,0x806,0x86DD,0x8100,0xffff,0x842,0x22F3,0x6003,0x8035,0x809B,0x80F3,0x8137,0x8138,0x8204,0x8808,0x8809,0x8819,0x8847,0x8848,0x8863,0x8864,0x8870,0x887B,0x888E,0x8892,0x889A,0x88A2,0x88A4,0x88A8,0x88AB,0x88CC,0x88CD,0x88E1,0x88E3,0x88E5,0x88E7,0x8902,0x8902,0x8906,0x8914,0x8915,0x892F,0x9000,0x9100,0xCAFE])/IP(src="192.168.10.10",dst="192.168.10.20")/"xxx"

e4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=0x800)/IP(src="192.168.10.10",dst="192.168.10.20",version=(0,15))/"xxx"

e5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/"xxx"

elist=[p for p in e1]+[p for p in e2]+[p for p in e3]+[p for p in e4]+[p for p in e5]

if elist:
	#print "Ether list=",len(elist)
	wrpcap('Ether.cap',elist)

#IP Layer
'''
Packets of this combination include 

        Ether() - Default field values taken for this layer

        IP() - Fields manipulated all possible ways for this layer

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''

i1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",proto=1)/"xxx"

i2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",proto=17)/"xxx"

i3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",proto=103)/"xxx"

i4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",proto=(0,255))/"xxx"

i5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",version=(0,15))/"xxx"

i6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=(0,15))/"xxx"

i7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=19)/"xxx"

i8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",chksum=[0x00,0xdbac,0xffff])/"xxx"

i9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[0,2,4,6,7,9,15,65535],len=[10,15,25,40,68,65535])/"xxx"

i10=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=(0,19))/"xxx"

i11=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[0,4,9,15],len=[10,15,40],chksum=[0x00,0xdbac,0xffff])/"xxx"

i12=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",flags=[(0,4),6,7])/"xxx"

i13=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",frag=[0,48,8191])/"xxx"

i14=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ttl=[0,255])/"xxx"

i15=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",tos=[0,255])/"xxx"

i16=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/"xxx"

i17=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",version=[1,4,5,6])/"xxx"

i18=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[2,6,7,9])/"xxx"


ilist=[p for p in i1]+[p for p in i2]+[p for p in i3]+[p for p in i4]+[p for p in i5]+[p for p in i6]+[p for p in i7]+[p for p in i8]+[p for p in i9]+[p for p in i10]+[p for p in i11]+[p for p in i12]+[p for p in i13]+[p for p in i14]+[p for p in i15]+[p for p in i16]+[p for p in i17]+[p for p in i18]

if ilist:
	#print "IP Length=",len(ilist)
	wrpcap('IP.cap',ilist)

#Ether and IP
'''
Packets of this combination include 

        Ether()/IP() - Fields manipulated all possible ways for these layers

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''

ei1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",proto=1)/"xxx"

ei2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",proto=17)/"xxx"

ei3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",proto=103)/"xxx"

ei4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",proto=(0,255))/"xxx"

ei5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",version=(0,15))/"xxx"

ei6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[0,5,12,15])/"xxx"

ei7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=19)/"xxx"

ei8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",chksum=[0x00,0xdbac,0xffff])/"xxx"

ei9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=[0,5,10,19])/"xxx"

ei10=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[0,4,9,15],len=[10,15,40],chksum=[0x00,0xdbac,0xffff])/"xxx"

ei11=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/"xxx"


eilist=[p for p in ei1]+[p for p in ei2]+[p for p in ei3]+[p for p in ei4]+[p for p in ei5]+[p for p in ei6]+[p for p in ei7]+[p for p in ei8]+[p for p in ei9]+[p for p in ei10]+[p for p in ei11]

if eilist:
        #print "Ether and IP packets count=",len(eilist)
        wrpcap('Ether+IP.cap',eilist)

#Ether and TCP 
'''
Packets of this combination include 

	IP() - Default values are taken for this layer

        Ether()/TCP() - Fields manipulated all possible ways for these layers

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''


et1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,dataofs=[10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10])/"xxx"

et2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/fuzz(TCP(sport=8826,dport=9826))/"xxx"

et3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,dataofs=[0,4,10,61])/"xxx"

et4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,chksum=[0x00,0xdbac,0xffff])/"xxx"

et5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,window=[0,8193])/"xxx"

et6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,chksum=[0xbdca,0xffff,0x0000],dataofs=[0,4,5,10,61])/""

et7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,flags="A")/"xxx"

et8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,seq=[0,345631],ack=[0,1,2321233])/"xxx"

et9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826)/""

et10=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826,dataofs=0x0)/""

etlist=[p for p in et1]+[p for p in et2]+[p for p in et3]+[p for p in et4]+[p for p in et5]+[p for p in et6]+[p for p in et7]+[p for p in et8]+[p for p in et9]+[p for p in et10]

if etlist:
        #print "Ether and TCP packets count=",len(etlist)
        wrpcap('Ether+TCP.cap',etlist)

#Ether and UDP
'''
Packets of this combination include 

        IP() - Default values are taken for this layer

        Ether()/UDP() - Fields manipulated all possible ways for these layers

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''


eu1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/fuzz(UDP())/"xxx"

eu2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/fuzz(UDP()/NTP(version=4))/"xxx"

eu3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826)/"xxx"

eu4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826,len=[6,8,9,10,11,(13,17),20,65535])/"xxx"

eu5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826,chksum=[0x00,0xdbac,0xffff])/"xxx"

eu6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826,len=[(0,7),8,9,10,11,(13,17),20,65535],chksum=[0x00,0xdbac,0xffff])/"xxx"

eu7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826,len=[0,7,8,9,20,35])/"xxx"

eu8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826,len=7)/"xxx"

eu9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826,len=17)/"xxx"


eulist=[p for p in eu1]+[p for p in eu2]+[p for p in eu3]+[p for p in eu4]+[p for p in eu5]+[p for p in eu6]+[p for p in eu7]+[p for p in eu8]+[p for p in eu9]
if eulist:
        #print "Ether and UDP packets count=",len(eulist)
        wrpcap('Ether+UDP.cap',eulist)


#Ether and ICMP
'''
Packets of this combination include 

        IP() - Default values are taken for this layer

        Ether()/ICMP() - Fields manipulated all possible ways for these layers

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''


eiic1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=0,code=[1,10,15])/"xxx"

eiic2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=[1,2,6,7,19,(20,29),31,50,100,255],code=[0,2,8,10,15])/"xxx"

eiic3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=5,code=[4,10,15])/"xxx"

eiic4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=11,code=[2,10,15])/"xxx"

eiic5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=12,code=[3,10,15])/"xxx"

eiic6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=[(8,10),(13,18),30],code=[1,3,6,9,15])/"xxx"

eiic7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(chksum=[0x0000,0xdabc,0xffff])/"xxx"

eiic8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/fuzz(ICMP())/"xxx"


eiiclist=[p for p in eiic1]+[p for p in eiic2]+[p for p in eiic3]+[p for p in eiic4]+[p for p in eiic5]+[p for p in eiic6]+[p for p in eiic7]+[p for p in eiic8]

if eiiclist:
        #print "Ether+ICMP packets count=",len(eiiclist)
        wrpcap('Ether+ICMP.cap',eiiclist)

#Ether ,IP and ICMP
'''
Packets of this combination include 

        Ether()/IP()/ICMP() - Fields manipulated all possible ways for these layers

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''


eicm1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x600,0x800,0x806])/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=[(8,10),(13,18),30],code=[0,1,5,10,15])/"xxx"

eicm2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x600,0x800,0x806])/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=0,code=[0,1,10,15],chksum=[0x0,0xdbac,0xffff])/"xxx"

eicm3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=(20,27))/ICMP()/"xxx"

eicm4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",proto=(0,255))/ICMP()/"xxx"

eicm5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[6,7])/ICMP()/"xxx"

eicm6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",chksum=[0x0,0xdbac,0xffff])/ICMP()/"xxx"

eicm7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",chksum=[0x0,0xdbbc,0xffff])/ICMP(chksum=[0x00,0xcdba,0xffff])/"xxx"

eicm8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",ihl=(0,15))/ICMP()/"xxx"

eicm9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=[1,10,15,19,28,65535])/ICMP()/"xxx"

eicm10=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[0,10,15],len=[10,15,19,20,23,27,28,65535])/ICMP()/"xxx"

eicm11=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",version=(0,15),proto=1)/ICMP()/"xxx"

eicm12=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[0,10,15],len=[10,25],chksum=[0xdcca,0xffff,0x00])/ICMP()/"xxx"

eicm13=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP()/"xxx"

eicm14=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=23)/ICMP()/"xxx"

eicm15=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=27)/ICMP()/"xxx"

eicm16=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=28)/ICMP()/"xxx"

eicm17=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",proto=[6,17])/ICMP()/"xxx"

eicm18=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",ihl=2,version=3)/ICMP()/"xxx"

eicm19=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD])/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=0,code=[0,1,10,15],chksum=[0x0,0xdbac,0xffff])/"xxx"

eicm20=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806])/IP(src="192.168.10.10",dst="192.168.10.20")/ICMP(type=[1,2,6,7,19,20,29,31,255],code=[0,10,15],chksum=0xdbac)/"xxx"

eicmlist=[p for p in eicm1]+[p for p in eicm2]+[p for p in eicm3]+[p for p in eicm4]+[p for p in eicm5]+[p for p in eicm6]+[p for p in eicm7]+[p for p in eicm8]+[p for p in eicm9]+[p for p in eicm10]+[p for p in eicm11]+[p for p in eicm12]+[p for p in eicm13]+[p for p in eicm14]+[p for p in eicm15]+[p for p in eicm16]+[p for p in eicm17]+[p for p in eicm18]+[p for p in eicm19]+[p for p in eicm20]

if eicmlist:
        #print "Ether+IP+ICMP packets count=",len(eicmlist)
        wrpcap('Ether+IP+ICMP.cap',eicmlist)

#Ether ,IP and TCP List
'''
Packets of this combination include 

        Ether()/IP()/TCP() - Fields manipulated all possible ways for these layers

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''

etcp1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=[20,30,40,50])/TCP(sport=8826,dport=9826)/"xxx"

etcp2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=39)/TCP(sport=8826,dport=9826)/"xxx"

etcp3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=40)/TCP(sport=8826,dport=9826,dataofs=10)/"xxx"

etcp4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",proto=(0,255))/TCP(sport=8826,dport=9826)/"xxx"

etcp5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[2,6,7,9])/TCP(sport=8826,dport=9826)/"xxx"

etcp6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=68)/TCP(sport=8826,dport=9826,dataofs=12)/"xxx"

etcp7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",chksum=[0x00,0xdbac,0xffff])/TCP(sport=8826,dport=9826,chksum=[0x00,0xdbac,0xffff])/"xxx"

etcp8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[0,5,10,12,15])/TCP(sport=8826,dport=9826)/"xxx"

etcp9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[0,5,10,15],len=[20,23,27,28,65535])/TCP(sport=8826,dport=9826)/"xxx"

etcp10=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800])/IP(src="192.168.10.10",dst="192.168.10.20",flags=[(0,4),6,7])/TCP(sport=8826,dport=9826)/"xxx"

etcp11=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800])/IP(src="192.168.10.10",dst="192.168.10.20",frag=[0,48,8191])/TCP(sport=8826,dport=9826)/"xxx"

etcp12=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800])/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[0,5,10,15],len=[20,23,25],chksum=[0xdcca,0xffff,0x00])/TCP(sport=8826,dport=9826)/"xxx"

etcp13=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",version=(0,15),proto=6)/TCP(sport=8826,dport=9826)/"xxx"

etcp14=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826)/"xxx"

etcp15=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=[20,25,30,35,40])/TCP(sport=8826,dport=9826)/"xxx"

etcp16=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=[41,50])/TCP(sport=8826,dport=9826)/"xxx"

etcp17=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=53)/TCP(sport=8826,dport=9826)/"xxx"

etcp18=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=40)/TCP(sport=8826,dport=9826,dataofs=40)/"xxx"

etcp19=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",proto=17)/TCP(sport=8826,dport=9826)/"xxx"

etcp20=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20")/TCP(sport=8826,dport=9826)/"xxx"

etcp21=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",proto=(0,255))/TCP(sport=8826,dport=9826)/"xxx"

etcp22=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=[20,30,40,50])/TCP(sport=8826,dport=9826)/"xxx"

etcplist=[p for p in etcp21]+[p for p in etcp22]+[p for p in etcp1]+[p for p in etcp2]+[p for p in etcp3]+[p for p in etcp4]+[p for p in etcp5]+[p for p in etcp6]+[p for p in etcp7]+[p for p in etcp8]+[p for p in etcp9]+[p for p in etcp10]+[p for p in etcp11]+[p for p in etcp12]+[p for p in etcp13]+[p for p in etcp14]+[p for p in etcp15]+[p for p in etcp16]+[p for p in etcp17]+[p for p in etcp18]+[p for p in etcp19]+[p for p in etcp20]

if etcplist:
        #print "Ether+IP+TCP packets count=",len(etcplist)
        wrpcap('Ether+IP+TCP.cap',etcplist)


#Ether,IP and UDP list
'''
Packets of this combination include 

        Ether()/IP()/UDP() - Fields manipulated all possible ways for these layers

Generated all possible combinations of packets into an array and stored them in a pcap file  

'''


eud1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=(20,27))/UDP(sport=8826,dport=9826)/"xxx"

eud2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5DC,0x600,0x800,0x806,0x86DD,0x8100])/IP(src="192.168.10.10",dst="192.168.10.20",proto=(0,255))/UDP(sport=8826,dport=9826)/"xxx"

eud3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",flags=[(0,4),6,7])/UDP(sport=8826,dport=9826)/("x"*224)

eud4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=28)/UDP(sport=8826,dport=9826,len=[0,7,9,10,20])/"xxx"

eud5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=28)/UDP(sport=8826,dport=9826,chksum=[0x00,0xffff,0xdbac])/"xxx"

eud6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[2,6,7,11,20])/UDP(sport=8826,dport=9826)/"xxx"

eud7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",flags="MF")/UDP(sport=8826,dport=9826)/("X"*224)

eud8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5DC,0x5DD,0x600,0x800,0x806])/IP(src="192.168.10.10",dst="192.168.10.20",version=(0,15),proto=17)/UDP(sport=8826,dport=9826)/"xxx"

eud9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",len=[20,28,31,40])/UDP(sport=8826,dport=9826)/"xxx"

eud10=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06",type=[0x5D2,0x5DC,0x5DD,0x600,0x800,0x806,0x86DD,0x8100,0xffff])/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[0,2,5,10,15])/UDP(sport=8826,dport=9826)/"xxx"

eud11=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",chksum=[0x0,0xdbac,0xffff])/UDP(sport=8826,dport=9826)/"xxx"

eud12=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",chksum=[0x0,0xdbbc,0xffff])/UDP(sport=8826,dport=9826,chksum=[0x00,0xcdba,0xffff])/"xxx"

eud13=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",ihl=[0,3,5,10,15],len=[20,23,25],chksum=[0xdcca,0xffff,0x00])/UDP(sport=8826,dport=9826)/"xxx"

eud14=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20")/UDP(sport=8826,dport=9826)/"xxx"

eud15=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",frag=[0,48,8191])/UDP(sport=8826,dport=9826)/("x"*224)

eud16=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=27)/UDP(sport=8826,dport=9826)/"xxx"

eud17=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",len=[23,35])/UDP(sport=8826,dport=9826)/"xxx"

eud18=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",proto=6)/UDP(sport=8826,dport=9826)/"xxx"

eudlist=[p for p in eud1]+[p for p in eud2]+[p for p in eud3]+[p for p in eud4]+[p for p in eud5]+[p for p in eud6]+[p for p in eud7]+[p for p in eud8]+[p for p in eud9]+[p for p in eud10]+[p for p in eud11]+[p for p in eud12]+[p for p in eud13]+[p for p in eud14]+[p for p in eud15]+[p for p in eud16]+[p for p in eud17]+[p for p in eud18]

if eudlist:
        #print "Ether+IP+UDP packets count=", len(eudlist)
        wrpcap('Ether+IP+UDP.cap',eudlist)

#IP Options Validation
'''
Generated all possible combinations of IP options validation packets into an array and stored them in a pcap file  

'''

iv1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x27"+"X"*38))/TCP(sport=8826,dport=9826)

iv2=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x27"+"X"*39))/TCP(sport=8826,dport=9826)

iv3=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x27"+"X"*40))/TCP(sport=8826,dport=9826)

iv4=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x28"+"X"*38))/TCP(sport=8826,dport=9826)

iv5=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x28"+"X"*39))/TCP(sport=8826,dport=9826)

iv6=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x28"+"X"*40))/TCP(sport=8826,dport=9826)

iv7=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x27"+"X"*36))/TCP(sport=8826,dport=9826)

iv8=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x28"+"X"*36))/TCP(sport=8826,dport=9826)

iv9=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x29"+"X"*40))/TCP(sport=8826,dport=9826)

iv10=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x29"+"X"*39))/TCP(sport=8826,dport=9826)

iv11=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x29"+"X"*38))/TCP(sport=8826,dport=9826)

iv12=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x29"+"X"*36))/TCP(sport=8826,dport=9826)

iv13=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x26"+"X"*40))/TCP(sport=8826,dport=9826)

iv14=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x26"+"X"*36))/TCP(sport=8826,dport=9826)

iv15=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x26"+"X"*38))/TCP(sport=8826,dport=9826)

iv16=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/IP(src="192.168.10.10",dst="192.168.10.20",options=IPOption("\x02\x26"+"X"*39))/TCP(sport=8826,dport=9826)

ivlist=[p for p in iv1]+[p for p in iv2]+[p for p in iv3]+[p for p in iv4]+[p for p in iv5]+[p for p in iv6]+[p for p in iv7]+[p for p in iv8]+[p for p in iv9]+[p for p in iv10]+[p for p in iv11]+[p for p in iv12]+[p for p in iv13]+[p for p in iv14]+[p for p in iv15]+[p for p in iv16]

if ivlist:
	wrpcap('Ipoptions.cap',ivlist)
#ARP PACKET
'''
Generated all possible combinations of ARP cache poisoning attack packets into an array and stored them in a pcap file  

'''

arp1=Ether(src="00:50:56:01:02:03",dst="00:50:56:04:05:06")/ARP(op=2,hwsrc="00:50:56:01:02:03",psrc="192.168.10.10",pdst="192.168.10.20",hwdst="00:50:56:04:05:06")
arplist=[p for p in arp1]

if arplist:
	wrpcap('arpcachepoison.cap',arplist)
#Printing lengths

print "--------------TOTAL PACKET COUNTS GENERATED--------------------------\n"


print "Ether -",len(elist)
print "IP -",len(ilist)
print "ICMP -",len(iclist)
print "TCP -",len(tlist)
print "UDP -",len(ulist)
print "Attacks -",len(alist)
print "IP option packets-",len(ivlist)
print "ARP cache poisoning-",len(arplist)
print "\n"
print "IP+ICMP -",len(icmlist)
print "IP+TCP -",len(tcplist)
print "IP+UDP -",len(udlist)
print "Ether+IP -",len(eilist)
print "Ether+ICMP -",len(eiiclist)
print "Ether+TCP -",len(etlist)
print "Ether+UDP -",len(eulist)
print "\n"
print "Ether+IP+ICMP -",len(eicmlist)
print "Ether+IP+TCP -",len(etcplist)
print "Ether+IP+UDP -",len(eudlist)





















	

