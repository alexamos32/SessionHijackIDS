#! /usr/bin/python3
#---------- IMPORTS -----------
import logging 
import threading 
import time
from scapy.all import *
from modules import ArpLog
from modules import PktLog
from modules import UserLog 
import uuid
import re
from modules import RotatingFileOpener
import traceback



#-----------PRINTING TIME-----------
def get_datetime(seconds):
    secDate= time.localtime(seconds)
    datestring = str(secDate.tm_hour) +':' + str(secDate.tm_min) + ':' + str(secDate.tm_sec) + ': ' + str(secDate.tm_mday) + '/' + str(secDate.tm_mon) + '/' + str(secDate.tm_year)
    return datestring

def get_timestamp(seconds):
    secDate= time.localtime(seconds)
    timestring = str(secDate.tm_hour) +':' + str(secDate.tm_min) + ':' + str(secDate.tm_sec)
    return timestring


#---------- LOGGING PACKETS -----------
def log_packet(pkt): 
    sip = ''
    dip = ''
    sport = -1
    dport = -1
    protocol = ''
    timestamp = time.time()
    try:
        #Check for IPv4 or 6 and save src and dst IP
        if IP in pkt:
            sip = pkt[IP].src
            dip = pkt[IP].dst
            if pkt[IP].proto == 'igmp':
                protocol = 'igmp'
        elif pkt.getlayer(IPv6):
            sip = pkt[IPv6].src
            dip = pkt[IPv6].dst
            if pkt[IPv6].nh == 'ICMPv6':
                protocol = 'ICMPv6'            
        
        #Save src and dst ports
        if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
        elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

        #If ARP log arp packet
        if ARP in pkt:
            #op = 2 is an arp reply, op = 1 is a request
            sip = pkt[ARP].psrc
            dip = pkt[ARP].pdst
            sport = 219
            dport = 219
            protocol = 'ARP'

            if pkt[ARP].op == 2:
                #Saving Arp data to ArpLog
                mac = pkt[ARP].hwsrc
                if not(mac == selfmac):
                    arpLogLock.acquire()
                    try:
                        arpLog.add_reply(mac, timestamp)
                    except Exception:
                        traceback.print_exc() 
                    finally:
                        arpLogLock.release() 
                
        elif ICMP in pkt:
            protocol = 'ICMP'
        elif DNS in pkt:
            protocol = 'DNS'
        #Saving common protocols
        elif TCP in pkt:
            #Log Username Attempts
            if sport == 20 or dport == 20 or sport == 21 or dport == 21:
                protocol = 'FTP'
                if pkt.getlayer(Raw):
                    data = pkt.getlayer(Raw).load
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
            
    except Exception:
        traceback.print_exc() 
        pkt.show()





#----------THREAD FUNCTIONS -----------

#Monitor for Attacks
def monitor_thread():
    while True:
        time.sleep(60)
        arpspoofList = list()
        userList = list()
        #Get list of host that have sent >=10 arp replies in 1 min
        arpLogLock.acquire()
        try:  
            arpspoofList = arpLog.check_arpspoof()
        finally:
            arpLogLock.release()
        
        #Get list of users with logins >=2
        userLogLock.acquire()
        try:
            userList = userLog.check_login_count()
        finally:
            userLogLock.release()
        
        #print(*userList)

        arpLen = len(arpspoofList)  
        userLen = len(userList)

        #Report Arpspoof if detected
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
        
        #if Multiple user attempts AND
        #Mac of a user attempt == mac of Arpoof sender, Detect Session Hijack
        if userLen > 0:
            i=0
            while i < userLen:
                isFound = False
                for mac in userList[i+1]:
                    if mac in attackerMac:
                        if userList[i] in usersStolen:
                            continue
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
    sniff(prn=log_packet, store=0)


#Cleanup Thread, Run every minute
def cleanup_thread():
    pktLogTimer = time.time()
    log = None
    while True:
        time.sleep(60)
        
        #Run Arplog cleanup
        arpLogLock.acquire()
        try:
            arpLog.cleanup()
        finally:
            arpLogLock.release()
        
        #Run UserLog cleanup
        userLogLock.acquire()
        try:
            userLog.cleanup()
        finally:
            userLogLock.release()
        
        #Clear packet log and write to log file
        currentTime = time.time()
        if currentTime - 600 >= pktLogTimer: 
            pktLogLock.acquire()
            try:
                log = pktLog.log
                pktLog.cleanup()
            finally: 
                pktLogLock.release()

            if(len(log) > 0):
                entries = list()
                for packet in log:
                    entries.append(get_timestamp(packet.timestamp) + ' \t\t' + str(packet.sip) + ' \t\t' + str(packet.sport) + ' \t\t' + str(packet.dip) + ' \t\t' + str(packet.dport) + ' \t\t' + str(packet.protocol)+' \n')
                logger.write(entries)
                entries.clear()
        

try:
    #Creating File log object
    logger = RotatingFileOpener.RotatingFileOpener('log', prepend='Pkt_Log_Data-', append='.txt')
    logger.enter()

    selfmac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))

    arpLog = ArpLog.ArpLog()
    pktLog = PktLog.PktLog()
    userLog = UserLog.UserLog()

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
except Exception:
    traceback.print_exc() 