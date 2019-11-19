#! /usr/bin/python3

import sys
import logging 
import threading 
import time
import datetime
from scapy.all import *
from ArpLog import ArpLog
from PktLog import PktLog


#TODO:  Finish clear method to clear replies that are older than 30 minutes
#       Create thread to logs arp replies
#       Create thread to monitor for Session Hijack conditions to be met
#       Create thread that sleeps for 10 minutes then runs clearOldReplies and continues sleeping
#       NOTE: I think all threads will have to be daemons as there will be no need to rejoin them
#       Add Dictionary for storing FTP usernames and timestamps


class PktLog:
    def __init__(self, srcIP, dstIP, srcPort, dstPort, protocol):
        self.srcIP = srcIP
        self.dstIP = dstIP
        self.srcPort = srcPort
        self.protocol = protocol
        self.timestamp = datetime.now().timestamp()


#Thread function for running the packet sniffer
def packet_sniff_thread(name):
    sniff(prn=log_packet, filter='arp', store=0)
    #sniff(prn=log_arp_packets, store=0)

#Logging sniffed Arp packets
def log_arp(sip, timestamp):
    if arpLog.searchIP(sip):
        arpLog.addReply(sip, timestamp)
    else:
        arpLog.addIp(sip, timestamp)
    #arpLog.printLog()


#Sniffing FTP Telnet Username

#STARTING CODE FOR SNIFFING USERNAME
#elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
#    if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
#        data = pkt[Raw].load()
#        if 'USER ' in data:
#            user = data.split('USER ')[1].strip()
#            if arpLog.searchUser(user):
#                #ADD METHOD FOR LOGGING USER ATTEMPT
#                pass
#            else:
#                arpLog.addUser(user)
            


def log_packet(pkt):
    return     
    sip = ''
    dip = ''
    sport = -1
    dport = -1
    protocol = ''
    timestamp = datetime.now().timestamp()
    if ARP in pkt:
        #op = 2 is an arp reply, op = 1 is a request
        if pkt[ARP].op == 2:
            #Saving pkt data
            sip = pkt[ARP].psrc
            dip = pkt[ARP].pdst
            protocol = 'ARP'          
            log_arp()

    elif ICMP in pkt:
        sip = pkt[IP].src
        dip = pkt[IP].dst
        protocol = 'ICMP'
    elif DNS in pkt:
        sip = pkt[IP].src
        dip = pkt[IP].dst
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        protocol = 'DNS'


    elif TCP in pkt:
        sip = pkt[IP].src
        dip = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        #Saving common protocols
        if sport == 20 or sport == 21 or dport == 20 or dport == 21:
            protocol = 'FTP'
            #TODO: CALL USERNAME SNIFF FUNCTION
        elif sport == 22 or dport == 22:
            protocol = 'SSH'
        elif sport == 23 or dport == 23:
            protocol = 'SSH'
            #TODO: CALL USERNAME SNIFF FUNCTION
        elif sport == 25 or dport == 25:
            protocol = 'SMTP'
        elif sport == 80 or dport == 80:
            protocol = 'HTTP'
        elif sport == 110 or dport == 110:
            protocol = 'POP'
        elif sport == 143 or dport == 143:
            protocol = 'IMAP'
        elif sport == 443 or dport == 443:
            protocol = 'HTTPS'
        #Otherwise default to TCP
        else:
            protocol = 'TCP'
        
    elif UDP in pkt:
        sip = pkt[IP].src
        dip = pkt[IP].dst
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        protocol = 'UDP'

        #TODO: CALL FUNCTION TO STORE THE PACKET IN pktLog
        

def monitor_thread(name):
    while True:
        arpspoof_list = arpLog.check_arpspoof()
        if len(arpspoof_list)>0:
            print("Arpspoof detected from: ", arpspoof_list[0])
        time.sleep(5)

arpLog = ArpLog()
pktLog = list()

sniff_thread = threading.Thread(target=packet_sniff_thread, args=(1,))
sniff_thread.start()

mon_thread = threading.Thread(target=monitor_thread, args=(2,))
mon_thread.start()