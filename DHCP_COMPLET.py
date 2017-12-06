#!/usr/bin/python3.5
# -*- coding=utf-8 -*-

#Dynamic Host Configuration Protocol (DHCP, protocole de configuration dynamique des hôtes) est un protocole réseau dont le rôle est d’assurer la configuration automatique des paramètres IP d’une station ou d'une machine, notamment en lui affectant automatiquement une adresse IP et un masque de sous-réseau.
#DHCP fonctionnement: DHCP discover => DHCP offer => DHCP request => DHCP Acknowlegement => DHCP release
#Ce script permet de demander une adresse IP d'un serveur DHCP

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#Ignorer l'erreur de IPv6 lors l'utilisation de Scapy
from scapy.all import *
import multiprocessing
import optparse
import struct
from Change_MAC_To_Bytes import Change_MAC_To_Bytes
from GET_MAC import GET_MAC
from Change_Chaddr_To_MAC import Change_Chaddr_To_MAC
from DHCP_Discover import DHCP_Discover_Sendonly
from DHCP_Request import DHCP_Request_Sendonly

def DHCP_Monitor_Control(pkt):
	try:
		if pkt.getlayer(DHCP).fields['options'][0][1]== 1:#Si on trouve une packet contenant 'DHCP Discover', on l'affiche
			print('On trouve DHCP Discover，MAC:',end='')
			MAC_Bytes = pkt.getlayer(BOOTP).fields['chaddr']
			MAC_ADDR = Change_Chaddr_To_MAC(MAC_Bytes) #Voir 'Change_Chaddr_To_MAC.py'
			print(MAC_ADDR)
			print('Options dans le paquet DISCOVER:')
			for option in pkt.getlayer(DHCP).fields['options']:
				if option == 'end':
					break
				print('%-15s ==> %s' %(str(option[0]),str(option[1])))			
		elif pkt.getlayer(DHCP).fields['options'][0][1]== 2:#Si on trouve une packet contenant 'DHCP offer', on l'affiche
			options = {}
			MAC_Bytes = pkt.getlayer(BOOTP).fields['chaddr']
			MAC_ADDR = Change_Chaddr_To_MAC(MAC_Bytes)
			#On met les information dans un dictionaire
			options['MAC'] = MAC_ADDR
			options['client_id'] = Change_MAC_To_Bytes(MAC_ADDR)
			print('DHCP OFFER， IP fournie:' + pkt.getlayer(BOOTP).fields['yiaddr'])#yiaddr: Client IP Addr Given by Srvr (BootP)
			print('Options dans le paquet OFFER:')
			for option in pkt.getlayer(DHCP).fields['options']:
				if option == 'end':
					break
				print('%-15s ==> %s' %(str(option[0]),str(option[1])))
			options['requested_addr'] = pkt.getlayer(BOOTP).fields['yiaddr']
			for i in pkt.getlayer(DHCP).fields['options']:
				if i[0] == 'server_id' :
					options['Server_IP'] = i[1]
			Send_Request = multiprocessing.Process(target=DHCP_Request_Sendonly, args=(Global_IF,options))#On demande cette adresse IP
			Send_Request.start()
		elif pkt.getlayer(DHCP).fields['options'][0][1]== 3:#Si on trouve une packet contenant 'DHCP request', on l'affiche
			print('DHCP Request，IP demandée:' + pkt.getlayer(BOOTP).fields['yiaddr'])
			print('Options dans le paquet REQUEST:')
			for option in pkt.getlayer(DHCP).fields['options']:
				if option == 'end':
					break
				print('%-15s ==> %s' %(str(option[0]),str(option[1])))
		elif pkt.getlayer(DHCP).fields['options'][0][1]== 5:##Si on trouve une packet contenant 'DHCP ACK', on l'affiche
			print('DHCP ACK，IP confirmée:' + pkt.getlayer(BOOTP).fields['yiaddr'])
			print('Options dans le paquet ACK:')
			for option in pkt.getlayer(DHCP).fields['options']:
				if option == 'end':
					break
				print('%-15s ==> %s' %(str(option[0]),str(option[1])))
	except Exception as e:   
		print(e)
		pass

def DHCP_FULL(ifname, MAC, timeout = 10):
	global Global_IF
	Global_IF = ifname
	Send_Discover = multiprocessing.Process(target=DHCP_Discover_Sendonly, args=(Global_IF,MAC))#Mutiprocesseur.
	Send_Discover.start()
	sniff(prn=DHCP_Monitor_Control, filter="port 68 and port 67", store=0, iface=Global_IF, timeout = timeout)# Sniff fonction est équivalent à TCPdump

	
#Définissons des options
if __name__ == "__main__":
	#Example 
    parser = optparse.OptionParser('python3 DHCP_COMPLET.py -i interface')
    parser.add_option('-i', dest = 'ifname', type = 'string', help = 'interface')
    (options, args) = parser.parse_args()
    ifname = options.ifname
    #Si la commande est sans option, on affiche l'example
    if ifname == None:
        print(parser.usage)
    else:
    	#On effectue la fonction et affiche le résultat 
        DHCP_FULL(ifname, GET_MAC(ifname))
