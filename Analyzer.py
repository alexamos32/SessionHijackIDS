#! /usr/bin/python3
#---------- IMPORTS -----------
import sys
import logging 
import threading 
import time
import datetime
from scapy.all import *
from ArpLog import ArpLog
from PktLog import PktLog
from UserLog import UserLog


#TODO:  Finish clear method to clear replies that are older than 30 minutes
#       Create thread to logs arp replies
#       Create thread to monitor for Session Hijack conditions to be met
#       Create thread that sleeps for 10 minutes then runs clearOldReplies and continues sleeping
#       NOTE: I think all threads will have to be DAEMONS as there will be no need to rejoin them
#       Add Dictionary for storing FTP usernames and timestamps






#Logging sniffed Arp packets
def log_arp(sip, timestamp):
    arpLog.add_reply(sip, timestamp)



#---------- LOGGING PACKETS -----------
def log_packet(pkt):
    #return     
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
            log_arp(sip, timestamp)

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
        if sport == 20 or dport == 20:
            protocol = 'FTP'
        if sport == 21 or dport == 21:
            protocol = 'FTP'
            data = pkt[RAW].load()
            if 'USER ' in data:
                user = data.split('USER ')[1].strip()
                userLog.add_user(user, sip, timestamp)
            #TODO: CALL USERNAME SNIFF FUNCTION
        elif sport == 22 or dport == 22:
            protocol = 'SSH'
        elif sport == 23 or dport == 23:
            protocol = 'TELNET'
            data = pkt[RAW].load()
            if 'USER ' in data:
                user = data.split('USER ')[1].strip()
                userLog.add_user(user, sip, timestamp)
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

        #Adding packet to the packetlog
        pktLog.log_packet(sip, dip, sport, dport, protocol, timestamp)        





#----------THREAD FUNCTIONS -----------

#Monitor for Attacks
def monitor_thread():
    while True:
        arpspoof_list = arpLog.check_arpspoof()
        if len(arpspoof_list)>0:
            print("Arpspoof detected from: ", arpspoof_list[0])
        time.sleep(5)


#Packet Sniffer
def packet_sniff_thread():
    sniff(prn=log_packet, filter='arp', store=0)
    #sniff(prn=log_arp_packets, store=0)


#Cleanup Thread
#Clears arplog of packets older than a minute
#Clears the packetlog of packets older than a day
def cleanup_thread():
    while True:
        time.sleep(60)
        arpLogLock.acquire()
        try:
            arpLog.cleanup()
        finally:
            arpLogLock.release()
        




arpLog = ArpLog()
pktLog = PktLog()
userLog = UserLog()
arpLogLock = threading.Lock()
pktLogLock = threading.Lock()

sniff_thread = threading.Thread(target=packet_sniff_thread)
sniff_thread.start()

mon_thread = threading.Thread(target=monitor_thread)
mon_thread.start()