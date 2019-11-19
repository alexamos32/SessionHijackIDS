class PktLog:
    def __init__(self, srcIP, dstIP, srcPort, dstPort, protocol):
        self.srcIP = srcIP
        self.dstIP = dstIP
        self.srcPort = srcPort
        self.protocol = protocol
        self.timestamp = datetime.now().timestamp()
