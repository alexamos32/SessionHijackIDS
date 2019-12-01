#! /usr/bin/python3
import time
#TODO: turn arplog into a dict that will save arppackets with an mac address, timestamp and count
class ArpLog:
    def __init__(self):
        self.arp = dict()


    def add_reply(self, mac, timestamp):
        if mac in self.arp:
            self.arp[mac]["timestamp"].append(timestamp)
            self.arp[mac]["count"] +=1
        else:
            self.arp[mac] = dict()
            self.arp[mac]["count"] = 1
            self.arp[mac]["timestamp"] = [timestamp]

    def search_ip(self, mac):
        if mac in self.arp:
            return True
        return False

    def cleanup(self):
        time1min = time.time() - 60
        #loop through each ip and remove all replies older than 1 min
        for i in self.arp:
            j=0
            if self.arp[i]['count'] == 0:
                continue
            #loop through timestamps and delete old ones
            while self.arp[i]['timestamp'][j] < time1min:
                del(self.arp[i]['timestamp'][j])
                self.arp[i]['count'] -= 1
                if self.arp[i]['count'] == 0:
                    break         
        return
    #Print Arp Log
    def print_log(self):
        for i in self.arp:
            print("MAC: ", i, "Count: ", self.arp[i]["count"])

    #return log length
    def log_length(self):
        return len(self.arp)
    
    #returns a list of ips and response counts for any ips breaking the 10 response threshold
    #Meaning arp-spoofing is happening from those IPs
    def check_arpspoof(self):
        temp = list()
        for mac in self.arp:
            if self.arp[mac]["count"] >= 10:
                temp.append(mac)
                temp.append(self.arp[mac]['timestamp'][0])
        return temp

