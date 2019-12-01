#! /usr/bin/python3
#---------- IMPORTS -----------
import sys
import logging 
import threading 
import time

from scapy.all import *
from ArpLog import ArpLog
from PktLog import PktLog
from UserLog import UserLog 
import uuid
import re
#import datetime

#TODO:  Finish clear method to clear replies that are older than 30 minutes
#       Create thread to logs arp replies
#       Create thread to monitor for Session Hijack conditions to be met
#       Create thread that sleeps for 10 minutes then runs clearOldReplies and continues sleeping
#       NOTE: I think all threads will have to be DAEMONS as there will be no need to rejoin them
#       Add Dictionary for storing FTP usernames and timestamps


#-----------PRINTING TIME-----------
def get_datetime(seconds):
    secDate= time.localtime(seconds)
    datestring = str(secDate.tm_hour) +':' + str(secDate.tm_min) + ':' + str(secDate.tm_sec) + ': ' + str(secDate.tm_mday) + '/' + str(secDate.tm_mon) + '/' + str(secDate.tm_year)
    return datestring

#---------- LOGGING PACKETS -----------
def log_packet(pkt):
    #return     
    sip = ''
    dip = ''
    sport = -1
    dport = -1
    protocol = ''
    timestamp = time.time()
    #print(timestamp)
    try:
        if IP in pkt:
            sip = pkt[IP].src
            dip = pkt[IP].src
        elif IPv6 in pkt:
            sip = pkt[IPv6].src
            dip = pkt[IPv6].src
        
        if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
        elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

        if ARP in pkt:
            #op = 2 is an arp reply, op = 1 is a request
            if pkt[ARP].op == 2:
                #Saving pkt data
                sip = pkt[ARP].psrc
                dip = pkt[ARP].pdst
                mac = pkt[ARP].hwsrc
                protocol = 'ARP'         
                arpLogLock.acquire()
                try:
                    arpLog.add_reply(mac, timestamp)
                finally:
                    arpLogLock.release() 
                
        elif ICMP in pkt:
            protocol = 'ICMP'
        elif DNS in pkt:
            protocol = 'DNS'

        elif TCP in pkt:
            #Saving common protocols
            if sport == 20 or dport == 20 or sport == 21 or dport == 21:
                protocol = 'FTP'
                if pkt.getlayer(Raw):
                    data = pkt.getlayer(Raw).load
                    #print(data)
                    if 'USER ' in str(data):
                        mac = pkt.getlayer(Ether).src
                        user = str(data).split('USER ')[1].strip()
                        user = user.replace('\\r\\n\'','')
                        if not user == 'anonymous':
                            userLogLock.acquire()
                            try:
                                userLog.add_user(user, mac, timestamp)
                            finally:
                                userLogLock.release()

                        #userLog.print_log()

            elif sport == 22 or dport == 22:
                protocol = 'SSH'
            elif sport == 23 or dport == 23:
                protocol = 'TELNET'
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
            protocol = 'UDP'

        #Adding packet to the packetlog
        pktLogLock.acquire()
        try:
            pktLog.log_packet(sip, dip, sport, dport, protocol, timestamp)        
        finally:
            pktLogLock.release()
            
    except Exception as e:
        print("Exception Occured")
        print(e)
        pkt.show()





#----------THREAD FUNCTIONS -----------

#Monitor for Attacks
def monitor_thread():
    
    while True:
        time.sleep(65)

        #print("Attacker List")
       # print(*(attackerMac))
        
        
        arpspoofList = list()
        userList = list()
        #pktLog.print_log()
        #arpspoof_list = arpLog.check_arpspoof()
        #if len(arpspoof_list)>0:
        #    print("Arpspoof detected from: ", arpspoof_list[0])
        #time.sleep(5)
        arpLogLock.acquire()
        try:  
            arpspoofList = arpLog.check_arpspoof()

        finally:
            arpLogLock.release()
        
        userLogLock.acquire()
        try:
            userList = userLog.check_login_count()
        finally:
            userLogLock.release()

        arpLen = len(arpspoofList)  
        userLen = len(userList)
        if arpLen > 0:
            i = 0
            while i < arpLen:
                mac = arpspoofList[i]
                if not mac in attackerMac:
                    attackerMac.append(mac)
                    attackStart.append(arpspoofList[i+1])
                    print('----ARP SPOOFING DETECTED----')
                    print('Spoofing Source MAC: ', mac)
                    datestring = get_datetime(arpspoofList[i+1])
                    print('Spoof Started At: ', datestring)
                    print('-----------------------------')
                
                i+=2
        
        if userLen > 0:
            #print("WHAT")
            i=0
            while i < userLen:
                isFound = False
                for mac in userList[i+1]:
                    #print('User, ',mac)
                    if mac in attackerMac:
                        if userList[i] in usersStolen:
                            continue
                       # print("HEEYYYY")
                        isFound = True
                        break
                
                if isFound:
                    print('----SESSION HIJACK DETECTED----')
                    print('Attacker MAC Address: ', mac)
                    print('Credentials Stolen for User: ', userList[i])
                    print('-------------------------------')
                    usersStolen.append(userList[i])
                i +=2


            

    

#Packet Sniffer
def packet_sniff_thread():
#sniff(prn=log_packet, filter='arp', store=0)
    sniff(prn=log_packet, store=0)


#Cleanup Thread
#Clears arplog of packets older than a minute
#Clears the packetlog of packets older than a day
def cleanup_thread():
    while True:
        time.sleep(60)

        arpLogLock.acquire()
        try:
            arpLog.cleanup()
           # arpLog.print_log()
        finally:
            arpLogLock.release()
        
        userLogLock.acquire()
        try:
            userLog.cleanup()
        finally:
            userLogLock.release()

        
        



selfmac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
arpLog = ArpLog()
pktLog = PktLog()
userLog = UserLog()
arpLogLock = threading.Lock()
pktLogLock = threading.Lock()
userLogLock = threading.Lock()

attackerMac = list()
attackStart = list()
usersStolen = list()

sniff_thread = threading.Thread(target=packet_sniff_thread)
sniff_thread.start()

cleanup_thread = threading.Thread(target=cleanup_thread)
cleanup_thread.start()

mon_thread = threading.Thread(target=monitor_thread)
mon_thread.start()