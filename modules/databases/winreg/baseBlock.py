# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009 ArxSys
# 
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.
# 
# See http://www.digital-forensic.org for more information about this
# project. Please do not directly contact any of the maintainers of
# DFF for assistance; the project provides a web site, mailing lists
# and IRC channels for your use.
# 
# Author(s):
#  Jeremy Mounier <jmo@digital-forensic.org>
# 


from api.exceptions.libexceptions import *
import binascii
import struct

class baseBlock():
    def __init__(self, parent):
        self.parser = parent
        self.hive = parent.hive

        if self.readMagic():
            self.readSequenceNumbers()
            self.readTimeStamp()
            self.readVersions()
            self.readOffsets()
#            self.readFirstUnknow()
        else:
            self.rootkeyoffset = 0


    def readMagic(self):
        # Read Magic Number and check if file is a valid hive
        try:
            self.hive.seek(0)
            buff = self.hive.read(4)
            if buff == "regf":
                return True
            else:
                return False
        except vfsError, e:
            print "Base block read Magic ERROR"

    def readSequenceNumbers(self):
        #  fields match if hive was properly synchronized.
        try:
            buff = self.hive.read(8)
            res = struct.unpack('II', buff)
            if res[0] == res[1]:
                print "Sequence Number matchs : Hive was properly synchronized"
        except vfsError, e:
            print "Base block read Sequence ERROR"

    def readTimeStamp(self):
        try:
            self.timestamp = self.hive.read(8)
        except vfsError, e:
            print "Base block read Time stamp ERROR"
        
    def readVersions(self):
        try:
            buff = self.hive.read(16)
            res = struct.unpack('IIII', buff)
            self.majorv = res[0]
            self.minorv = res[1]
            self.uktype = res[2]
            self.ukformat = res[3]
        except vfsError, e:
            print "Base block read Versions ERROR"

    def readOffsets(self):
        try:
            buff = self.hive.read(8)
            res = struct.unpack('II', buff)
            self.rootkeyoffset = res[0]
            self.lasthbinoffset = res[1]
        except vfsError, e:
            print "Base block read Offset ERROR"
        
