#!/usr/bin/python3.4
# -*- coding=utf-8 -*-

#Ce script permet de filtrer l'information de l'adresse IP d'une carte réseau lorsqu'on utilise la commande "ifconfig interface".

import os
import re
import optparse

def get_ip_address_ifconfig(iface):
    data = os.popen("ifconfig " + iface).read()#on exécute la commande ‘ifconifg’ et instance un objet 'data'.
    words = data.split()##On scinde l'information et met tous les morceaux dans une list "words"

    ip_found = 0#si on trouve l'adresse IP
    network_found = 0#si on trouve le réseau
    broadcast_found = 0#si on trouve l'adresse broadcast
    location = 0#location dans la liste 'words'
    ip_index = 0
    network_index = 0
    broadcast_index = 0

    for x in words:
        if re.findall('(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', x):#Expression réguilière
            result = re.findall('(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', x)
            if result[0][3] == '0':#Si le dernier élément dans la liste est '0', c'est l'adresse du réseau.
                network_found = 1
                network_index = location
                location = location + 1
            elif result[0][3] == '255':#Si le dernier élément dans la liste est '255', c'est l'adresse broadcast.
                broadcast_found = 1
                broadcast_index = location
                location = location + 1
            else:
                ip_found = 1
                ip_index = location
                location = location + 1
        else:
            location = location + 1
    if ip_found == 1:
        ip = words[ip_index]
    else:
        ip = None

    if network_found == 1:
        network = words[network_index]
    else:
        network = None

    if broadcast_found == 1:
        broadcast = words[broadcast_index]
    else:
        broadcast = None

    get_ip_address_result = {}#créér un dictionarire contenant: IP, adresse broadcast, mask.
    get_ip_address_result['ip_address'] = ip
    get_ip_address_result['network_mask'] = network
    get_ip_address_result['broadcast_address'] = broadcast
    return get_ip_address_result

if __name__ == "__main__":
    parser = optparse.OptionParser('python3 GET_IP_IFCONFIG.py --ifname interface')
    parser.add_option('--ifname', dest = 'ifname', type = 'string', help = 'interface')
    (options, args) = parser.parse_args()
    ifname = options.ifname
    if ifname == None:
        print(parser.usage)
    else:
        for x,y in get_ip_address_ifconfig(ifname).items():
            print(x,y)


