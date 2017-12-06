#!/usr/bin/python3.5
# -*- coding=utf-8 -*-


#le 3er étape du DHCP: DHCP request

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#Ignorer l'erreur de IPv6 lors l'utilisation de Scapy
from scapy.all import *
from Change_MAC_To_Bytes import Change_MAC_To_Bytes
import time

def DHCP_Request_Sendonly(ifname, options, wait_time = 1):# On attend une seconde pour recevoir le packet. 'options' se trouvent dans le message DHCP offer provenant du serveur DHCP.
	request = Ether(dst='ff:ff:ff:ff:ff:ff',
		            src=options['MAC'],
		            type=0x0800)/IP(src='0.0.0.0', 
		            				dst='255.255.255.255')/ UDP(dport=67,sport=68)/ BOOTP(op=1,
		            																	  chaddr=options['client_id'] + b'\x00'*10,
		            																	  siaddr=options['Server_IP'],)/DHCP(options=[('message-type','request'),
	 				 																												  ('server_id', options['Server_IP']),
	 				 																												  ('requested_addr', options['requested_addr']),
	 				 																												  ('client_id', b'\x01' + options['client_id']),
	 				 																												  ('param_req_list', b'\x01\x06\x0f,\x03!\x96+'), ('end')])		            																	  
	if wait_time != 0:
		time.sleep(wait_time)
		sendp(request, iface = ifname, verbose=False)
	else:
		sendp(request, iface = ifname, verbose=False)		
