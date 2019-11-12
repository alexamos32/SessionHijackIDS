#! /usr/bin/python3

import sys
from scapy.all import *


def check_login(pkt, user, passwd):
    try:
        if '230' in pkt[Raw].load:
            print('USER: ' + user)
            print('PASS:' + passwd)
            return
        else:
            return
    except Exception:
        return



#Checking packet type (FTP)
def check_pkt_type(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
            return True
        else:
            return False
    else:
        return False


