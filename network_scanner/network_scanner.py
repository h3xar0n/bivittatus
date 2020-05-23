#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_target():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP address or CIDR address.")
    input_options = parser.parse_args()
    if not input_options.target:
        parser.error("[-] Please specify a target IP address or CIDR address. Use --help for more info")
    return input_options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_scan(clients_list):
    if clients_list:
        line = "\n-----------------------------------------"
        tabs = "\t\t"
        print("IP" + tabs + "\tMAC Address" + line)
        for element in clients_list:
            print(element["ip"] + tabs + element["mac"])
    else:
        print("[-] Could not detect any addresses")


options = get_target()

scan_target = scan(options.target)

print_scan(scan_target)
