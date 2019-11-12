#! /usr/bin/python3

import sys
import logging 
import threading 
import time
import datetime
from scapy.all import *


#TODO:  Finish clear method to clear replies that are older than 30 minutes
#       Create thread to logs arp replies
#       Create thread to monitor for Session Hijack conditions to be met
#       Create thread that sleeps for 10 minutes then runs clearOldReplies and continues sleeping
#       NOTE: I think all threads will have to be daemons as there will be no need to rejoin them

class ArpLog:
    def __init__(self):
        self.value = dict()

    def addIp(self, IPaddr):
        self.value[IPaddr] = dict()
        self.value[IPaddr]["count"] = 1
        self.value[IPaddr]["timestamp"] = [datetime.now().timestamp()]

    def addReply(self, IPaddr):
        self.value[IPaddr]["timestamp"].append(datetime.now().timestamp())
        self.value[IPaddr]["count"] +=1

    def searchIP(self, IPaddr):
        if IPaddr in self.value:
            return True

    def clearOldReplies(self):
        time30min = datetime.now().timestamp() - 1800
        #loop through each ip and remove all replies older than 30 min
        for i in self.value:
            oldest = -1
            j=0
            #loop through timestamps and 
            for j in (0, len(self.value[i]["timestamp"])-1):
                if self.value[i]["timestamp"][j] >= time30min:
                    j -=1
                    break
            #Clear all timestamps if all timestamps are old
            if j == (len(self.value[i]["timestamp"])-1):
                self.value[i]["timestamp"].clear()
                self.value[i]["count"] = 0
                continue
            
            #Go to next IP if all timestamps are recent
            elif j < 0:
                continue

            #Remove Old elements
            else:
                length = len(self.value[i]["timestamp"])
                #create a sublist of elements newer than 30 min
                temp = self.value[i]["timestamp"][j+1:length-1]
                self.value[i]["count"] -= (j+1)
                self.value[i]["timestamp"] = temp
                continue
            
        return
    #Print Arp Log
    def printLog(self):
        for i in self.value:
            print("IP: ", i, "Count: ", self.value[i]["count"])

    #return log length
    def log_length(self):
        return len(self.value)
    
    #returns a list of ips and response counts for any ips breaking the 10 response threshold
    #Meaning arp-spoofing is happening from those IPs
    def check_arpspoof(self):
        temp = list()
        for addr in self.value:
            if self.value[addr]["count"] >= 10:
                temp.append(addr)
                temp.append(self.value[addr]["count"])
        return temp


#Thread function for running the packet sniffer
def packet_sniff_thread(name):
    sniff(prn=log_arp_packets, filter='arp', store=0)

#Logging sniffed Arp packets
def log_arp_packets(pkt):
    if ARP in pkt and pkt[ARP].op == 2:
        srcIP = pkt[ARP].psrc
        if arpLog.searchIP(srcIP):
            arpLog.addReply(srcIP)
        else:
            arpLog.addIp(srcIP)
        #pkt.show()
        arpLog.printLog()
        return 
        

def monitor_thread(name):
    while True:
        arpspoof_list = arpLog.check_arpspoof()
        if len(arpspoof_list)>0:
            print("Arpspoof detected from: ", arpspoof_list[0])
        time.sleep(5)

arpLog = ArpLog()

sniff_thread = threading.Thread(target=packet_sniff_thread, args=(1,))
sniff_thread.start()

mon_thread = threading.Thread(target=monitor_thread, args=(2,))
mon_thread.start()