#! /usr/bin/python3
class PktLog:
    def __init__(self):
        self.log = list()
        self.i = 0

    def log_packet(self, sip, dip, sport, dport, protocol, timestamp):
        self.log.append(Packet(sip, dip, sport, dport, protocol, timestamp))

    
    def print_log(self):
        length = len(self.log) 
        for n in (self.i, len(self.log)-1):
            print(self.log[n].sip, ' ', self.log[n].protocol, ' ', self.log[n].timestamp)
        self.i = len(self.log)
    
    def cleanup(self):
        self.log = list()
        self.i = 0
        


class Packet:
    def __init__(self, sip, dip, sport, dport, protocol, timestamp):
        self.sip = sip
        self.dip = dip
        self.sport = sport
        self.dport = dport
        self.protocol = protocol
        self.timestamp = timestamp

