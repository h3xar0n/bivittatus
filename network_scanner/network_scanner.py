#!/usr/bin/env python

import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    line = "\n-----------------------------------------"
    tabs = "\t\t"
    print("IP" + tabs + "\tMAC Address" + line)
    for element in answered_list:
        print(element[1].psrc + tabs + element[1].hwsrc)


scan("192.168.124.2/24")
