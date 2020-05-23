#!/usr/bin/env python

import scapy.all as scapy

packet = scapy.ARP(op=2, pdst="192.168.124.142", hwdst="00:0c:29:81:c9:c0", psrc="192.168.124.2")