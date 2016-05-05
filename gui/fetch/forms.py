#List of Forms that are going to be displayed to the user
from django import forms

#Form used for pickup a pcap option
class GetForm(forms.Form):
	sourceip = forms.CharField(required=False)
	sourcemac = forms.CharField(required=False)
	destip = forms.CharField(required=False)
	destmac = forms.CharField(required=False)
	srcport = forms.CharField(required=False)
	dstport = forms.CharField(required=False)
	destination = forms.CharField()

#Form used for crafting Ether pcap 
class FormEther(forms.Form):
	packets_count = forms.IntegerField(required=False)	
	srcmac_ether = forms.CharField(required=False)
	dstmac_ether = forms.CharField(required=False)
	type_ether = forms.CharField(required=False)
	src_ip = forms.CharField(required=False)
	dst_ip = forms.CharField(required=False)
	a = forms.CharField()
		
#Form used for crafting IP pcap
class FormIP(forms.Form):
	packets_count = forms.IntegerField(required=False)	
	srcmac_ether = forms.CharField(required=False)
	dstmac_ether = forms.CharField(required=False)
	src_ip = forms.CharField(required=False)
	dst_ip = forms.CharField(required=False)
	ihl_ip = forms.CharField(required=False)
	len_ip = forms.CharField(required=False)
	proto_ip = forms.CharField(required=False)
	version_ip = forms.CharField(required=False)
	chksum_ip = forms.CharField(required=False)
	flags_ip = forms.CharField(required=False)
	b = forms.CharField()

#Form used for crafting TCP pcap
class FormTCP(forms.Form):
	packets_count = forms.IntegerField(required=False)
	srcmac_ether = forms.CharField(required=False)
	dstmac_ether = forms.CharField(required=False)
	type_ether = forms.CharField(required=False)
	src_ip = forms.CharField(required=False)
	dst_ip = forms.CharField(required=False)
	ihl_ip = forms.CharField(required=False)
	len_ip = forms.CharField(required=False)
	proto_ip = forms.CharField(required=False)
	version_ip = forms.CharField(required=False)
	chksum_ip = forms.CharField(required=False)
	flags_ip = forms.CharField(required=False)
	sport_tcp = forms.CharField(required=False)
	dport_tcp = forms.CharField(required=False)
	dataofs_tcp = forms.CharField(required=False)
	chksum_tcp = forms.CharField(required=False)
	c = forms.CharField()

#Form used for crafting UDP pcap
class FormUDP(forms.Form):
	packets_count = forms.IntegerField(required=False)
	srcmac_ether = forms.CharField(required=False)
	dstmac_ether = forms.CharField(required=False)
	type_ether = forms.CharField(required=False)
	src_ip = forms.CharField(required=False)
	dst_ip = forms.CharField(required=False)
	ihl_ip = forms.CharField(required=False)
	len_ip = forms.CharField(required=False)
	proto_ip = forms.CharField(required=False)
	version_ip = forms.CharField(required=False)
	chksum_ip = forms.CharField(required=False)
	flags_ip = forms.CharField(required=False)
	sport_udp = forms.CharField(required=False)
	dport_udp = forms.CharField(required=False)
	chksum_udp = forms.CharField(required=False)
	len_udp = forms.CharField(required=False)
	d = forms.CharField()

#Form used for crafting ICMP pcap
class FormICMP(forms.Form):
	packets_count = forms.IntegerField(required=False)
	srcmac_ether = forms.CharField(required=False)
	dstmac_ether = forms.CharField(required=False)
	type_ether = forms.CharField(required=False)
	src_ip = forms.CharField(required=False)
	dst_ip = forms.CharField(required=False)
	ihl_ip = forms.CharField(required=False)
	len_ip = forms.CharField(required=False)
	proto_ip = forms.CharField(required=False)
	version_ip = forms.CharField(required=False)
	chksum_ip = forms.CharField(required=False)
	flags_ip = forms.CharField(required=False)
	type_icmp = forms.CharField(required=False)
	code_icmp = forms.CharField(required=False)
	chksum_icmp = forms.CharField(required=False)
	e = forms.CharField()






	

