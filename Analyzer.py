#! /usr/bin/python3

import sys
from scapy.all import *

arpDict = {}

#Checking packet type (FTP)
#def check_pkt_type(pkt):
 #   if pkt.haslayer(TCP) and pkt.haslayer(Raw):
  #      if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
   #         return True
    #    else:
     #       return False
   # else:
    #    return False


#pkts = sniff(filter='arp', count=5)
#print(pkts.summary())


def log_arp_packets(pkt):
    if ARP in pkt and pkt[ARP].op == 2:
        srcIP = pkt[ARP].psrc
        if srcIP in arpDict:
            arpDict[srcIP] += 1
        else:
            arpDict[srcIP] = 1

        #pkt.show()
        print(arpDict)
        return #pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")
        


sniff(prn=log_arp_packets, filter='arp', store=0)   
        