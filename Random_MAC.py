#!/usr/bin/python3.5
# -*- coding=utf-8 -*-

#Ce script permet de générer une adresse MAC aléatoire.
import random


def hex():
	hex_mac = random.choice([1,2,3,4,5,6,7,8,9,'a','b','c','e','f'])
	return str(hex_mac)

def Random_MAC():
	MAC = hex() + hex() + ':' + hex() + hex() + ':' + hex() + hex() + ':' + hex() + hex() + ':' + hex() + hex() + ':' + hex() + hex()
	return MAC

if __name__ == '__main__':
	print(Random_MAC())
