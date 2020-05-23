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

# Errors:
#
# root@kali:~/PycharmProjects# pip3 install scapy-python3
# Requirement already satisfied: scapy-python3 in /usr/local/lib/python3.7/dist-packages (0.26)
# root@kali:~/PycharmProjects# python3 network_scanner/network_scanner.py -t 192.168.124.2/24
#
#         PIP package scapy-python3 used to provide scapy3k, which was a fork from scapy implementing python3 compatibility since 2016. This package was included in some of the Linux distros under name of python3-scapy. Starting from scapy version 2.4 (released in March, 2018) mainstream scapy supports python3. To reduce any confusion scapy3k was renamed to kamene.
# You should use either pip package kamene for scapy3k (see http://github.com/phaethon/kamene for differences in use) or mainstream scapy (pip package scapy, http://github.com/secdev/scapy).
#
# Traceback (most recent call last):
#   File "network_scanner/network_scanner.py", line 3, in <module>
#     import scapy.all as scapy
#   File "/usr/local/lib/python3.7/dist-packages/scapy/all.py", line 5, in <module>
#     raise Exception(msg)
# Exception:
#         PIP package scapy-python3 used to provide scapy3k, which was a fork from scapy implementing python3 compatibility since 2016. This package was included in some of the Linux distros under name of python3-scapy. Starting from scapy version 2.4 (released in March, 2018) mainstream scapy supports python3. To reduce any confusion scapy3k was renamed to kamene.
# You should use either pip package kamene for scapy3k (see http://github.com/phaethon/kamene for differences in use) or mainstream scapy (pip package scapy, http://github.com/secdev/scapy).
