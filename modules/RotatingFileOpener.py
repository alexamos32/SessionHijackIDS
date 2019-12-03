#! /usr/bin/python3
import os
import time

class RotatingFileOpener:
    def __init__(self, path, mode='a', prepend="", append=""):
        if not os.path.isdir(path):
            raise FileNotFoundError("Can't open directory '{}' for data output.".format(path))
        self.path = path
        self.prepend = prepend
        self.append = append
        self.mode = mode
        self.day = time.localtime().tm_mday

    def enter(self):
        self.filename = self.format_filename()
        self.file = open(self.filename, self.mode)
        self.file.write('Timestamp\tSourceIP\tSourcePort\tDestIP\tDestPort\tProtocol\n')
        self.file.write('____________________________________________________________________________________________________\n')
        self.file.close()
        return self

    def day_changed(self):
        return self.day != time.localtime().tm_mday

    def format_filename(self):
        return os.path.join(self.path, "{}{}{}".format(self.prepend, time.strftime("%Y%m%d"), self.append))
    
    def write(self, args):
        if self.day_changed():
            self.filename = self.format_filename()
        self.file = open(self.filename, self.mode)
        for arg in args:
            self.file.write(arg)
        self.file.close()
   
  