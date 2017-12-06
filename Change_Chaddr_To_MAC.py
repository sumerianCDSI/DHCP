#!/usr/bin/python3.5
# -*- coding=utf-8 -*-

#Dans le protocol Bootstrap (BootP), la taille de CHADDR (Client Hardare Addresse) est 16 octets dont 10 octest sont inutilisés. 
#Ce script permet de filtrer les permiers 6 octets qui correspond à l'adresse MAC dans CHADDR.

import struct

def Change_Chaddr_To_MAC(chaddr): 
	MAC_ADDR_INT_List = struct.unpack('>16B', chaddr)[:6]
	MAC_ADDR_List = []
	for MAC_ADDR_INT in MAC_ADDR_INT_List:
		if MAC_ADDR_INT < 16:
			MAC_ADDR_List.append('0' + str(hex(MAC_ADDR_INT))[2:])
		else:
			MAC_ADDR_List.append(str(hex(MAC_ADDR_INT))[2:])
	MAC_ADDR = MAC_ADDR_List[0] + ':' + MAC_ADDR_List[1] + ':' + MAC_ADDR_List[2] + ':' + MAC_ADDR_List[3] + ':' + MAC_ADDR_List[4] + ':' + MAC_ADDR_List[5]
	return MAC_ADDR
