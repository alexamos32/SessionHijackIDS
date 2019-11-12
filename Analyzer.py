#! /usr/bin/catcpython3

import sys
from scapy.all import *



#Checking packet type (ARP)
def check_pkt_type(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
            return True
        else:
            return False
    else:
        return False


pkts = sniff(filter='arp', count=5)
print(pkts.summary())