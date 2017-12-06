#!/usr/bin/python3.5
# -*- coding=utf-8 -*-


#Ce script permet de trouver l'adresse MAC d'une périphérique réseau (Uniquement pour l'OS linux)

import os
import re
import optparse


#Définissons une fonction avec un seul paramètre (le nom de la carte réseau)
def GET_MAC(iface):
	#On effectue la commande linux ifconfig iface et enregistre dans un objet "data"
    data = os.popen("ifconfig " + iface).read()
    #On scinde l'information et met tous les morceaux dans une list "words"
    words = data.split()
    found = 0
    location = 0
    index = 0
    for x in words:
    	#On cherche l'adresse MAC dans la list "words" en utilisant l'expression régulière "\w\w:\w\w:\w\w:\w\w:\w\w:\w\w"
        if re.match('\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', x):
            found = 1
            index = location
            break
        else:
            location = location + 1
    if found == 1:
        mac = words[index]
    else:
        mac = 'Mac not found'
    return mac

if __name__ == "__main__":
    parser = optparse.OptionParser('python3 GET_MAC.py --ifname interface')
    parser.add_option('--ifname', dest = 'ifname', type = 'string', help = 'interface')
    (options, args) = parser.parse_args()
    ifname = options.ifname
    if ifname == None:
        print(parser.usage)
    else:
        print(GET_MAC(ifname))


