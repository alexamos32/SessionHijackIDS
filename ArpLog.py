
#TODO: turn arplog into a dict that will save arppackets with an ip and time stamp and count
class ArpLog:
    def __init__(self):
        self.arp = dict()


    def addIp(self, IPaddr, timestamp):
        self.arp[IPaddr] = dict()
        self.arp[IPaddr]["count"] = 1
        self.arp[IPaddr]["timestamp"] = [timestamp]

    def addReply(self, IPaddr, timestamp):
        self.arp[IPaddr]["timestamp"].append(timestamp)
        self.arp[IPaddr]["count"] +=1

    def searchIP(self, IPaddr):
        if IPaddr in self.arp:
            return True
        else:
            return False

    def searchUser(self, user):
        if user in self.ftp:
            return True
        else:
            return False
    def clearOldReplies(self):
        time30min = datetime.now().timestamp() - 1800
        #loop through each ip and remove all replies older than 30 min
        for i in self.arp:
            oldest = -1
            j=0
            #loop through timestamps and 
            for j in (0, len(self.arp[i]["timestamp"])-1):
                if self.arp[i]["timestamp"][j] >= time30min:
                    j -=1
                    break
            #Clear all timestamps if all timestamps are old
            if j == (len(self.arp[i]["timestamp"])-1):
                self.arp[i]["timestamp"].clear()
                self.arp[i]["count"] = 0
                continue
            
            #Go to next IP if all timestamps are recent
            elif j < 0:
                continue

            #Remove Old elements
            else:
                length = len(self.arp[i]["timestamp"])
                #create a sublist of elements newer than 30 min
                temp = self.arp[i]["timestamp"][j+1:length-1]
                self.arp[i]["count"] -= (j+1)
                self.arp[i]["timestamp"] = temp
                continue
            
        return
    #Print Arp Log
    def printLog(self):
        for i in self.arp:
            print("IP: ", i, "Count: ", self.arp[i]["count"])

    #return log length
    def log_length(self):
        return len(self.arp)
    
    #returns a list of ips and response counts for any ips breaking the 10 response threshold
    #Meaning arp-spoofing is happening from those IPs
    def check_arpspoof(self):
        temp = list()
        for addr in self.arp:
            if self.arp[addr]["count"] >= 10:
                temp.append(addr)
                temp.append(self.arp[addr]["count"])
        return temp

