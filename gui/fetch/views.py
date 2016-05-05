'''
views.py --
	General Information
	File owner : Manoj Tammali
	Description : Python program getting the requests from the web pages and
		      providing the results back to the user,using back end program
'''
import sys
from scapy.all import *
from django.template.loader import get_template
from django.template import Context
from django.shortcuts import render, redirect
from fetch.forms import GetForm,FormIP, FormEther, FormTCP, FormUDP, FormICMP
from tool import fun1, fun2, fun3, fun4, fun5, fun6, fun7, fun8, fun9, fun10, fun11, fun12, fun13, fun14, fun15, fun16,fun17,fun18
import os, shutil, dpkt
from scapy.error import Scapy_Exception

#Displaying main.html form
def main(request):
	return render(request,'main.html',{
	})	
#Displaying index,html form
def index(request):
	return render(request, 'index.html', {
		'form' : GetForm(),
	})
#Handling the index form submitted in execute1 function 
def execute1(request):
	filepath = ""
	if request.method == "POST":
		form = GetForm(request.POST)
		if form.is_valid():
			values = form.cleaned_data
			route = values['destination']
			#Retreiving all the field values of the form by using hidden field and calling appropriate functions in backend program
			if route == 'etheronly':

				filepath = fun1(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'])

			elif route == 'etherudp':

				filepath = fun2(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'],values['srcport'],values['dstport'])

			elif route == 'ethertcp':

                                filepath = fun3(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'],values['srcport'],values['dstport'])
                                
	                elif route == 'ethericmp':
                                
				filepath = fun4(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'])

			elif route == 'security':
				
				filepath = fun5(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'])

 			elif route == 'TCP':
		
				filepath = fun6(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'],values['srcport'],values['dstport'])

			elif route == 'UDP':

				filepath = fun7(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'],values['srcport'],values['dstport'])

			elif route == 'ICMP':

				filepath = fun8(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'])

			elif route == 'EtherIPV4':

				filepath = fun9(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'])

			elif route == 'EtherIPV4ICMP':

				filepath = fun10(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'])

			elif route == 'EtherIPV4TCP':

				filepath = fun11(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'],values['srcport'],values['dstport'])

			elif route == 'EtherIPV4UDP':

				filepath = fun12(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'],values['srcport'],values['dstport'])
			
			elif route == 'IPV4':
				filepath = fun13(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'])

			elif route == 'IPV4TCP':
				filepath = fun14(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'],values['srcport'],values['dstport'])

			elif route =='IPV4UDP':

			 	filepath = fun15(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'],values['srcport'],values['dstport'])

			elif route == 'IPV4ICMP':
				filepath = fun16(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'])

			elif route == 'IPoptions':
				filepath = fun17(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'])

			elif route == 'ARP':
				filepath = fun18(values['sourceip'],values['sourcemac'],values['destip'],values['destmac'])
			

	
	return render(request, 'execute1.html', {
					'filepath': filepath
						})	
#Displaying upload html form and handling file submitted in that form
def upload(request):
	if request.method == "POST":
		myFile = request.FILES['myfile']
	
		TEMP_DEST = 'fetch/garbage'
		with open(TEMP_DEST, 'wb') as dest:
			shutil.copyfileobj(myFile,dest)
		try:
			_ = dpkt.pcap.Reader(open(TEMP_DEST))
		except:
			#File Thrown if not a valid pcap file
			return render(request, 'upload.html', {'fileUploaded':"Invalid File. Thrown into garbage"})
		
		DEST_DIR = 'fetch/repository/'
		destPath = os.path.join(DEST_DIR, myFile.name)
		#Check to dicard conflicting name pcaps that are already existing in repository when tried to upload
		if os.path.exists(destPath):
			return render(request, 'upload.html', {"fileUploaded": "File with that name already exists,file not uploaded"})
		#Copying all the file data into desired location
		with open(destPath, 'wb') as dest:
			with open(TEMP_DEST, 'rb') as source:
				shutil.copyfileobj(source, dest)
		#Modifying the pcap contents as per the repository standards		
                pkt = rdpcap('fetch/repository/' + myFile.name)
		i=0
		while i < len(pkt):
			if pkt[i].haslayer(IP):
				pkt[i][IP].src = "192.168.10.10"
				pkt[i][IP].dst = "192.168.10.20"
			if pkt[i].haslayer(Ether):
				pkt[i][Ether].src = "00:50:56:01:02:03"
				pkt[i][Ether].dst = "00:50:56:04:05:06"
			i=i+1
		wrpcap('fetch/repository/'+myFile.name,pkt)	
                				
		return render(request, 'upload.html', {'fileUploaded': "Uploaded file " + myFile.name,})
	else:
		return render(request, 'upload.html', {'fileUploaded':"",})

#Function to handle crafting packets logic
def craft(request):
	
	return render(request,'craft.html', {
		'formether' : FormEther(),
		'formip' : FormIP(),
		'formtcp' : FormTCP(),
		'formicmp' : FormICMP(),
		'formudp' : FormUDP()
	})
#Function to retrieve submitted data from the craft forms and craft packets and give back to user appropriately
def result(request):

	if request.method == 'POST':
		data = request.POST
		#Retreiving the submitted form by using hidden field		
		if 'a' in data:
			form = FormEther(data)		
			if form.is_valid():
				
				values = form.cleaned_data
				length = values.pop('packets_count')
				del values['a']
				
				#Field values checks appropriately done 	
					
				totallist = []
				fields = ('srcmac_ether', 'dstmac_ether', 'type_ether', 'src_ip', 'dst_ip')
				for key in fields:
					if values[key] == '':
						#Atleast one value in each field check
						return render(request, 'goback.html', {
                                                'errormsg': "Specify atleast one value in each field"
                                                })
					#Retrieve values specified in appropriate field
					elif key == 'type_ether':
						packets = []
						types = values[key].split(',')
						for i in xrange(len(types)):
							if '-' in types[i]:
								pair = types[i].split('-')
								start= int(pair[0],16)
								end= int(pair[1],16)+1
								if start > end:
									packets.extend(range(start,end,-1))
								else:
									packets.extend(range(start,end))
							else:
								packets.append(int(types[i],16))	
						
					else:
						packets = values[key].split(',')
					
					provided = len(packets)
					
					if provided < length:
						for i in xrange(length - provided):
							packets.append(packets[i % provided])
				
					
					elif provided != length and length is not None:
						#print provided, length
						return render(request, 'goback.html', {
						'errormsg': "You Entered less num of packets compared to some field values,go back and correct it"
						})
					totallist.append(packets)
				pktlist = []
				# if packets count is None, take all possible combinations to generate packets
				if length is None:
					for srcmac in totallist[0]:
						for dstmac in totallist[1]:
							for type_ in totallist[2]:
								for srcip in totallist[3]:
									for dstip in totallist[4]:
										pkt = Ether(src=srcmac, dst=dstmac, type=type_) / IP(src=srcip, dst=dstip)
										pktlist += [p for p in pkt]
				# else packets count specified, limit the packets to be generated
				else:
					for j in range(0,length):		
						pkt=Ether(src=totallist[0][j],dst=totallist[1][j],type=totallist[2][j])/IP(src=totallist[3][j],dst=totallist[4][j])
						pktlist += [p for p in pkt]
		
				wrpcap('fetch/static/Ether_craft.cap',pktlist)
        			filepath = 'Ether_craft.cap'

				return render(request, 'result.html', {
                                        'filepath': filepath
                                                })

		if 'b' in data:
			form = FormIP(data)
			if form.is_valid():
				values = form.cleaned_data
				length = values.pop('packets_count')
				del values['b']
				#Field values checks appropriately done
				totallist = []
				fields = ('srcmac_ether', 'dstmac_ether', 'src_ip', 'dst_ip','ihl_ip','len_ip','proto_ip','version_ip','chksum_ip','flags_ip')
				for key in fields:
					if values[key] == '':
						#Atleast one value in each field check
						return render(request, 'goback.html', {
                                                'errormsg': "Specify atleast one value in each field"
                                                })

					#Retrieve values specified in appropriate field
					elif key == 'ihl_ip' or key == 'len_ip' or key == 'proto_ip' or key == 'version_ip':
                                                packets = []
                                                types = values[key].split(',')
                                                for i in xrange(len(types)):
                                                        if '-' in types[i]:
                                                                pair = types[i].split('-')
                                                                start= int(pair[0])
                                                                end= int(pair[1])+1
								if start > end:
                                                                	packets.extend(range(start,end,-1))
								else:
									packets.extend(range(start,end))
                                                        else:
                                                                packets.append(int(types[i]))
					elif key == 'chksum_ip' or key == 'flags_ip':
                                                packets = []
                                                types = values[key].split(',')
                                                for i in xrange(len(types)):
                                                        if '-' in types[i]:
                                                                pair = types[i].split('-')
                                                                start= int(pair[0],16)
                                                                end= int(pair[1],16)+1
                                                                if start > end:
                                                                        packets.extend(range(start,end,-1))
                                                                else:
                                                                        packets.extend(range(start,end))
                                                        else:
                                                                packets.append(int(types[i],16))

					else:
						packets = values[key].split(',')
					
		                        provided = len(packets)
                                        if provided < length:
                                                for i in xrange(length - provided):
                                                        packets.append(packets[i % provided])

					elif provided != length and length is not None:
						return render(request, 'goback.html', {
							'errormsg': "You Entered less num of packets compared to some field values,go back and correct it"
						})
					totallist.append(packets)
			pktlist = []
			# if packets count is None, take all possible combinations to generate packets
			if length is None:
				for srcmac in totallist[0]:
                                                for dstmac in totallist[1]:
                                                        for srcip in totallist[2]:
                                                                for dstip in totallist[3]:
                                                                        for ihl_ in totallist[4]:
										for len_ in totallist[5]:
											for proto_ in totallist[6]:
												for version_ in totallist[7]:
													for chksum_ in totallist[8]:
														for flags_ in totallist[9]:
                                                                                					pkt = Ether(src=srcmac, dst=dstmac) / IP(src=srcip, dst=dstip, ihl=ihl_, len=len_, proto=proto_, version=version_, chksum=chksum_, flags=flags_)
                                                                                					pktlist += [p for p in pkt]
			# else packets count specified, limit the packets to be generated
			else:
				for j in range(0,length):
								
					pkt=Ether(src=totallist[0][j],dst=totallist[1][j])/IP(src=totallist[2][j],dst=totallist[3][j],ihl=totallist[4][j],len=totallist[5][j],proto=totallist[6][j],version=totallist[7][j],chksum=totallist[8][j],flags=totallist[9][j])

					pktlist += [p for p in pkt]
		
			wrpcap('fetch/static/IP_craft.cap',pktlist)
        		filepath = 'IP_craft.cap'

			return render(request, 'result.html', {
                                        'filepath': filepath
                                                })
			
			
		if 'c' in data:
			form = FormTCP(data)
			
			if form.is_valid():
				
				values = form.cleaned_data
				length = values.pop('packets_count')
				del values['c']
				#Field values checks appropriately done
				totallist= []
				fields = ('srcmac_ether','dstmac_ether','type_ether','src_ip','dst_ip','ihl_ip','len_ip','proto_ip','version_ip','chksum_ip','flags_ip','sport_tcp','dport_tcp','dataofs_tcp','chksum_tcp')
				for key in fields:
					if values[key] == '':
						#Atleast one value in each field check
						return render(request, 'goback.html', {
                                                'errormsg': "Specify atleast one value in each field"
                                                })

					#Retrieve values specified in appropriate field
				        elif key == 'type_ether' or key == 'chksum_ip' or key =='flags_ip' or key == 'chksum_tcp':
                                                packets = []
                                                types = values[key].split(',')
                                                for i in xrange(len(types)):
                                                        if '-' in types[i]:
                                                                pair = types[i].split('-')
                                                                start= int(pair[0],16)
                                                                end= int(pair[1],16)+1
                                                                if start > end:
                                                                        packets.extend(range(start,end,-1))
                                                                else:
                                                                        packets.extend(range(start,end))
                                                        else:
                                                        	packets.append(int(types[i],16))
			                elif key == 'ihl_ip' or key == 'len_ip' or key == 'proto_ip' or key =='version_ip' or key == 'sport_tcp' or key =='dport_tcp' or key == 'dataofs_tcp':
                                                packets = []
                                                types = values[key].split(',')
                                                for i in xrange(len(types)):
                                                        if '-' in types[i]:
                                                                pair = types[i].split('-')
                                                                start= int(pair[0])
                                                                end= int(pair[1])+1
                                                                if start > end:
                                                                        packets.extend(range(start,end,-1))
                                                                else:
                                                                        packets.extend(range(start,end))
                                                        else:
                                                                packets.append(int(types[i]))


					else:
						packets = values[key].split(',')
					
                                        provided = len(packets)
                                        if provided < length:
                                                for i in xrange(length - provided):
                                                        packets.append(packets[i % provided])
					elif provided != length and length is not None:
						return render(request, 'goback.html', {
							'errormsg': "You Entered less num of packets compared to some field values,go back and correct it"
						})
					totallist.append(packets)
			pktlist = []
			# if packets count is None, take all possible combinations to generate packets
			if length is None:
				 for srcmac in totallist[0]:
                                  for dstmac in totallist[1]:
				   for type_ in totallist[2]:
                                    for srcip in totallist[3]:
                                     for dstip in totallist[4]:
                                      for ihl_ in totallist[5]:
                                       for len_ in totallist[6]:
                                 	for proto_ in totallist[7]:
                                 	 for version_ in totallist[8]:
                                 	  for chksum_ in totallist[9]:
                                 	   for flags_ in totallist[10]:
				 	    for sport_ in totallist[11]:
				 	     for dport_ in totallist[12]:
				 	      for dataofs_ in totallist[13]:
				 	       for chksum2 in totallist[14]:
						pkt=Ether(src=srcmac, dst=dstmac, type=type_)/IP(src=srcip, dst=dstip, ihl=ihl_, len=len_, proto=proto_, version=version_, chksum=chksum_, flags=flags_)/TCP(sport=sport_, dport=dport_, dataofs=dataofs_, chksum=chksum2)
        					pktlist += [p for p in pkt]

			# else packets count specified, limit the packets to be generated
			else:
				for j in range(0,length):
								
					pkt = Ether(src =totallist[0][j],dst =totallist[1][j],type =totallist[2][j])/IP(src=totallist[3][j],dst=totallist[4][j],ihl=totallist[5][j],len=totallist[6][j],proto=totallist[7][j],version=totallist[8][j],chksum=totallist[9][j],flags=totallist[10][j])/TCP(sport=totallist[11][j],dport=totallist[12][j],dataofs=totallist[13][j],chksum=totallist[14][j])
					pktlist += [p for p in pkt]
		
			wrpcap('fetch/static/TCP_craft.cap',pktlist)
        		filepath = 'TCP_craft.cap'

			return render(request, 'result.html', {
                                        'filepath': filepath
                                                })

						
		if 'd' in data:
			form = FormUDP(data)
			
			if form.is_valid():
				
				values = form.cleaned_data
				length = values.pop('packets_count')
				del values['d']
				#Field values checks appropriately done
				totallist = []
				fields = ('srcmac_ether','dstmac_ether','type_ether','src_ip','dst_ip','ihl_ip','len_ip','proto_ip','version_ip','chksum_ip','flags_ip','sport_udp','dport_udp','chksum_udp','len_udp')
				for key in fields:
					if values[key] == '':
						 #Atleast one value in each field check
						 return render(request, 'goback.html', {
                                                'errormsg': "Specify atleast one value in each field"
                                                })

					#Retrieve values specified in appropriate field

                  	                elif key == 'type_ether' or key == 'chksum_ip' or key =='flags_ip' or key == 'chksum_udp':
                                                packets = []
                                                types = values[key].split(',')
                                                for i in xrange(len(types)):
                                                        if '-' in types[i]:
                                                                pair = types[i].split('-')
                                                                start= int(pair[0],16)
                                                                end= int(pair[1],16)+1
                                                                if start > end:
                                                                        packets.extend(range(start,end,-1))
                                                                else:
                                                                        packets.extend(range(start,end))
                                                        else:
                                                                packets.append(int(types[i],16))
					elif key == 'ihl_ip' or key =='len_ip' or key =='proto_ip' or key =='version_ip' or key =='sport_udp' or key =='dport_udp' or key == 'len_udp':
                                                packets = []
                                                types = values[key].split(',')
                                                for i in xrange(len(types)):
                                                        if '-' in types[i]:
                                                                pair = types[i].split('-')
                                                                start= int(pair[0])
                                                                end= int(pair[1])+1
                                                                if start > end:
                                                                        packets.extend(range(start,end,-1))
                                                                else:
                                                                        packets.extend(range(start,end))
                                                        else:
                                                                packets.append(int(types[i]))



					else:
						packets = values[key].split(',')
				
                                        provided = len(packets)
                                        if provided < length:
                                                for i in xrange(length - provided):
                                                        packets.append(packets[i % provided])
					elif provided != length and length is not None:
						return render(request, 'goback.html', {
							'errormsg': "You Entered less num of packets compared to some field values,go back and correct it"
						})
					totallist.append(packets)
			pktlist = []
			# if packets count is None, take all possible combinations to generate packets
			if length is None:
				 for srcmac in totallist[0]:
                                  for dstmac in totallist[1]:
                                   for type_ in totallist[2]:
                                    for srcip in totallist[3]:
                                     for dstip in totallist[4]:
                                      for ihl_ in totallist[5]:
                                       for len_ in totallist[6]:
                                        for proto_ in totallist[7]:
                                         for version_ in totallist[8]:
                                          for chksum_ in totallist[9]:
                                           for flags_ in totallist[10]:
                                            for sport_ in totallist[11]:
                                             for dport_ in totallist[12]:
                                              for chksum2 in totallist[13]:
                                               for len2 in totallist[14]:
                                                pkt=Ether(src=srcmac, dst=dstmac, type=type_)/IP(src=srcip, dst=dstip, ihl=ihl_, len=len_, proto=proto_, version=version_, chksum=chksum_, flags=flags_)/UDP(sport=sport_, dport=dport_, len=len2, chksum=chksum2)
                                                pktlist += [p for p in pkt]
		
			# else packets count specified, limit the packets to be generated
			else:	
				for j in range(0,length):
								
					pkt=Ether(src=totallist[0][j],dst=totallist[1][j],type=totallist[2][j])/IP(src=totallist[3][j],dst=totallist[4][j],ihl=totallist[5][j],len=totallist[6][j],proto=totallist[7][j],version=totallist[8][j],chksum=totallist[9][j],flags=totallist[10][j])/UDP(sport=totallist[11][j],dport=totallist[12][j],len=totallist[14][j],chksum=totallist[13][j])
					pktlist += [p for p in pkt]
		

			wrpcap('fetch/static/UDP_craft.cap',pktlist)
        		filepath = 'UDP_craft.cap'

			return render(request, 'result.html', {
                                        'filepath': filepath
                                                })
		
					
		if 'e' in data:
			form = FormICMP(data)
	
			if form.is_valid():
				
				values = form.cleaned_data
				length = values.pop('packets_count')
				del values['e']
				#Field values checks appropriately done
				totallist = []
				fields = ('srcmac_ether','dstmac_ether','type_ether','src_ip','dst_ip','ihl_ip','len_ip','proto_ip','version_ip','chksum_ip','flags_ip','type_icmp','code_icmp','chksum_icmp')
				for key in fields:
					if values[key] == '':
						#Atleast one value in each field check
						return render(request, 'goback.html', {
                                                'errormsg': "Specify atleast one value in each field"
                                                })
					#Retrieve values specified in appropriate field

		                        elif key == 'type_ether' or key =='chksum_ip' or key=='flags_ip' or key=='chksum_icmp':
                                                packets = []
                                                types = values[key].split(',')
                                                for i in xrange(len(types)):
                                                        if '-' in types[i]:
                                                                pair = types[i].split('-')
                                                                start= int(pair[0],16)
                                                                end= int(pair[1],16)+1
                                                                if start > end:
                                                                        packets.extend(range(start,end,-1))
                                                                else:
                                                                        packets.extend(range(start,end))
                                                        else:
                                                                packets.append(int(types[i],16))
					elif key == 'ihl_ip' or key == 'len_ip' or key =='proto_ip' or key =='version_ip' or key =='type_icmp' or key=='code_icmp':
                                                packets = []
                                                types = values[key].split(',')
                                                for i in xrange(len(types)):
                                                        if '-' in types[i]:
                                                                pair = types[i].split('-')
                                                                start= int(pair[0])
                                                                end= int(pair[1])+1
                                                                if start > end:
                                                                        packets.extend(range(start,end,-1))
                                                                else:
                                                                        packets.extend(range(start,end))
                                                        else:
                                                                packets.append(int(types[i]))



					else:
						packets = values[key].split(',')
		
                                        provided = len(packets)
                                        if provided < length:
                                                for i in xrange(length - provided):
                                                        packets.append(packets[i % provided])

					elif provided != length and length is not None:
						return render(request, 'goback.html', {
							'errormsg': "You Entered less num of packets compared to some field values,go back and correct it"
						})
					totallist.append(packets)
			pktlist = []
			# if packets count is None, take all possible combinations to generate packets
			if length is None:
				 for srcmac in totallist[0]:
                                  for dstmac in totallist[1]:
                                   for type_ in totallist[2]:
                                    for srcip in totallist[3]:
                                     for dstip in totallist[4]:
                                      for ihl_ in totallist[5]:
                                       for len_ in totallist[6]:
                                        for proto_ in totallist[7]:
                                         for version_ in totallist[8]:
                                          for chksum_ in totallist[9]:
                                           for flags_ in totallist[10]:
                                            for type2 in totallist[11]:
                                             for code_ in totallist[12]:
                                              for chksum2 in totallist[13]:
                                               pkt=Ether(src=srcmac, dst=dstmac, type=type_)/IP(src=srcip, dst=dstip, ihl=ihl_, len=len_, proto=proto_, version=version_, chksum=chksum_, flags=flags_)/ICMP(type=type2, code=code_, chksum=chksum2)
                                               pktlist += [p for p in pkt]
	
			# else packets count specified, limit the packets to be generated
			else:
				for j in range(0,length):
								
					pkt=Ether(src=totallist[0][j],dst=totallist[1][j],type=totallist[2][j])/IP(src=totallist[3][j],dst=totallist[4][j],ihl=totallist[5][j],len=totallist[6][j],proto=totallist[7][j],version=totallist[8][j],chksum=totallist[9][j],flags=totallist[10][j])/ICMP(type=totallist[11][j],code=totallist[12][j],chksum=totallist[13][j])
					pktlist += [p for p in pkt]
		

			wrpcap('fetch/static/ICMP_craft.cap',pktlist)
        		filepath = 'ICMP_craft.cap'

			return render(request, 'result.html', {
                                        'filepath': filepath
                                                })












