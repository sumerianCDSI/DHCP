#!/usr/bin/python3.5
# -*- coding=utf-8 -*-

#le 1er étape du DHCP: DHCP discover

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#Ignorer l'erreur de IPv6 lors l'utilisation de Scapy
from scapy.all import *
from GET_MAC import GET_MAC
from Change_MAC_To_Bytes import Change_MAC_To_Bytes
import time
import optparse

def DHCP_Discover_Sendonly(ifname, MAC, wait_time = 1):
	if wait_time != 0:
		time.sleep(wait_time)
		Bytes_MAC = Change_MAC_To_Bytes(MAC)
		#On construit un paquet de DHCP:
		discover = Ether(dst='ff:ff:ff:ff:ff:ff', src=MAC, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / UDP(dport=67,sport=68) / BOOTP(op=1, chaddr=Bytes_MAC + b'\x00'*10) / DHCP(options=[('message-type','discover'), ('param_req_list', b'\x01\x06\x0f,\x03!\x96+'), ('end')])
		#Enternet type 0x800: IPv4
		#DHCP client UDP port: 68
		#DHCP server UDP port: 67
		#Chaddr (Client hardware address): 6 octets de l'adresse MAC + 10 octets inutilisés
		#DHCP options: subnet=1, DNS=6, Domain Name=15, Gateway=3, ... (On peut les trouver dans Wireshark)
		sendp(discover, iface = ifname, verbose=False)
	else:
		Bytes_MAC = Change_MAC_To_Bytes(MAC)
		discover = Ether(dst='ff:ff:ff:ff:ff:ff', src=MAC, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / UDP(dport=67,sport=68) / BOOTP(op=1, chaddr=Bytes_MAC + b'\x00'*10) / DHCP(options=[('message-type','discover'), ('param_req_list', b'\x01\x06\x0f,\x03!\x96+'), ('end')])
		sendp(discover, iface = ifname, verbose=False)	

