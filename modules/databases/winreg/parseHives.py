# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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


from PyQt4.QtCore import *
from PyQt4.QtGui import *

from modules.databases.winreg.baseBlock import *

from api.vfs import *
from api.module.module import *
#from api.env.libenv import *
from api.types.libtypes import Variant, VMap, vtime
from api.vfs.libvfs import *
from api.exceptions.libexceptions import *

import binascii
import struct
import time

#Input : Hive (node)
class parseHive():
    def __init__(self, node, mfso):
        self.node = node
        self.mfso = mfso

        self.init()
        self.mfso.stateinfo = "0% Parse Base block"
        self.parseBaseBlock()
        if self.baseBlock.rootkeyoffset > 0:
            self.allocated[0] = 0x1000
            self.parseBinHeaders()
            self.mfso.stateinfo = "20% Create nodes and compute allocated space"
            self.parseRegistree(self.baseBlock.rootkeyoffset + self.blocksize)

#        print "Total keys : ", self.totalkeys
            
        self.hbinrootnode = Node("hbins", 0, self.node)
        self.hbins = []
        self.parseBinHeaders(False)

        self.computeUnallocatedSpace()


        allocoffsets = self.allocated.keys()
        allocoffsets.sort()
        unallocoffsets = self.unallocated.keys()
        unallocoffsets.sort()

#        for aoff in allocoffsets:
#          print "offset : ", aoff, " size : ", self.allocated[aoff]
#        print "==========================="
#        for uoff in unallocoffsets:
#          print "offset : ", uoff, " size : ", self.unallocated[uoff]

        self.unallocrootnode = Node("unallocaded_files", 0, self.node)
        hnode = fullUnallocatedNode(self.mfso, self.unallocrootnode, "unallocated", self.hive, self.unallocated)
        hhnode = fullUnallocatedNode(self.mfso, self.unallocrootnode, "allocated", self.hive, self.allocated)
        self.mfso.stateinfo = "100% Done"

        self.mfso.registerTree(self.node, self.rootkey) 

    def init(self):
        # Open hive
        self.hive = self.node.open()

        self.hivesize = self.node.size()
        self.blocksize = 0x1000

        self.totalkeys = 0

        self.allocated = {}
        self.unallocated = {}

        self.celltype = { "nk": 0x6b6e,
                          "lf": 0x666c,
                          "lh": 0x686c,
                          "ri": 0x6972,
                          "li": 0x696c
                          }

    def parseBaseBlock(self):
        self.baseBlock = baseBlock(self)
    
    def parseRegistree(self, offset, parent = None):
        celltype = self.readCellType(offset)
        if celltype == self.celltype["nk"]:
            self.parseKeyCell(offset, parent)
        elif self.isSubkeyList(celltype):
            self.parseSubkeyListCell(offset, parent)

    def isSubkeyList(self, celltype):
        if celltype == self.celltype["lf"] or self.celltype["lh"]:
            return True
        elif celltype == self.celltype["ri"] or self.celltype["li"]:
            return True
        else:
            return False

    def readCellType(self, offset):
        try:
            self.hive.seek(offset)
            buff = self.hive.read(6)
            res = struct.unpack('<IH', buff)
            return res[1]
        except vfsError, e:
            print "Base block read Magic ERROR"

    def parseKeyCell(self, offset, parent):
        try:
            self.hive.seek(offset)
            keybuff = self.hive.read(0x50)
            keystruct = struct.unpack('<IHHQIIIIIIIIIIIIIIIHH', keybuff)
            name = self.hive.read(keystruct[19])

            createdtime =  keystruct[3]
            sklistoffset = keystruct[8]
            vsklistoffset = keystruct[9]
            nvalues =  keystruct[10]
            vlistoffset = keystruct[11] + self.blocksize
            securityoffset = keystruct[12] + self.blocksize
            classoffset = keystruct[13] + self.blocksize
            namelen = keystruct[19]
            classnamelen = keystruct[20]

#            self.readClassName(classoffset + self.blocksize, classnamelen)
#        Parse_Class_Name (class_name_offset)
#        Parse_Value_List_Cell (value_list_offset)
            self.allocated[offset] = 0x50 + namelen
            if classnamelen > 0:
                self.allocated[classoffset] = classnamelen
#                print "HOHO ", classnamelen

            sklen = self.getSKLen(securityoffset)
            self.allocated[securityoffset] = sklen
#            print "HIHI ", sklen
            # If number of values > 0
            if nvalues > 0:
                self.allocated[vlistoffset] = (nvalues * 4) + 4
                valist = self.readValList((vlistoffset), nvalues)
                for val in valist:
                    self.getAllocatedValues(val + self.blocksize)
            else:
                valist = None

            if parent != None:
                key = keyNode(self.mfso, parent, name, self.hive, valist, offset, createdtime)
            else:
                self.rootkey = keyNode(self.mfso, parent, name, self.hive, valist, offset, createdtime)

            self.totalkeys += 1

            if sklistoffset < 0xffffffff:
                if parent != None:
                    self.parseRegistree(sklistoffset + self.blocksize, key)
                else:
                    self.parseRegistree(sklistoffset + self.blocksize, self.rootkey)
            
        except vfsError, e:
            print "Base block read Magic ERROR"

    def createdTime(self, vt):
        vtime.year = v

    def getAllocatedValues(self, offset):
        try:
            self.hive.seek(offset)
            vbuff = self.hive.read(24)
        except vfsError, e:
            print "Base block read Magic ERROR"

        vstruct = struct.unpack('<IHHHHIIHH', vbuff)
        
        vnamelen = vstruct[2]
        datalen_low = vstruct[3]
        datalen_high = vstruct[4]
        data_off = vstruct[5]
        if datalen_low > 4:
            self.allocated[offset] = 24 + vnamelen
            self.allocated[data_off + self.blocksize] = 4 + datalen_low
        else:
            self.allocated[offset] = 24 + vnamelen

    def computeUnallocatedSpace(self):
        prevoffset = 0

#        self.allocated.sort()
        allocoffsets = self.allocated.keys()
        allocoffsets.sort()

        for offset in allocoffsets:
#            print "offset : ", offset, "size : ", self.allocated[offset] 
            current_offset = offset + self.allocated[offset]
            if prevoffset < offset:
#                print "offset : ", prevoffset, " size : ", offset - prevoffset
                self.unallocated[prevoffset] = offset - prevoffset
            prevoffset = current_offset

        self.unallocated[self.hivesize] = 0

        # Create fullAllocated

        # Create all unallocated nodes
#        unallocoffsets = self.unallocated.keys()
#        unallocoffsets.sort()
#        for off in unallocoffsets:
#            name = "unallocated" + str(off)
#            hnode = unallocatedNode(self.mfso, self.unallocrootnode, name, self.hive, self.unallocated[off], off)


    def parseBinHeaders(self, allocate = True):
        binoffset = self.blocksize
        count = 0
        magic = 0x6e696268
        while (binoffset < self.hivesize) and (magic == 0x6e696268):
            try:
                self.hive.seek(binoffset)
                skbuff = self.hive.read(0x20)
                hbinstruct = struct.unpack("<IIIQQI", skbuff)
                
                magic = hbinstruct[0]
#                fromfirst = hbinstruct[1]
                size = hbinstruct[2]
#                uk1 = hbinstruct[3]
#                uk2 = hbinstruct[4]
#                relativetonext = hbinstruct[5]
#                print "binoffset : ", binoffset, " < ", self.hivesize
                if allocate:
                    self.allocated[binoffset] = 0x20
                else:
                    name = "hbin_" + str(count)
                    hnode = hbinNode(self.mfso, self.hbinrootnode, name, self.hive, size, binoffset)
                    self.hbins.append(hnode)
                binoffset += size
                count += 1
            except vfsError, e:
                print "Base block read Magic ERROR"

    def getSKLen(self, skoffset):
      try:
          self.hive.seek(skoffset)
          skbuff = self.hive.read(24)
          skstruct = struct.unpack("<IHHIIII", skbuff)
          # Don't forget security descriptor header (size 24 bytes)!
          return skstruct[6] + (24 * 2)

      except vfsError, e:
            print "Base block read Magic ERROR"

    def readClassName(self, offset, classnamelen):
        try:
            self.hive.seek(offset)
            cbuff = self.hive.read(classnamelen)
        except vfsError, e:
            print "Base block read Magic ERROR"
        

    def readValList(self, offset, nval):
        toread = nval * 4
        try:
            self.hive.seek(offset + 4)
            record = self.hive.read(toread)

            if (len(record) == toread):
                filt = "<" + str(nval) + "I"
                valoffsets = struct.unpack(str(filt), record);
                if (len(valoffsets) == nval):
                    return valoffsets
                else:
                    print "ERROR IN VALUE LIST"
        except vfsError, e:
            print "Error while reading value list"

    def parseSubkeyListCell(self, offset, parent):
        try:
            self.hive.seek(offset)
            buff = self.hive.read(8)
            res = struct.unpack('<IHH', buff)

            size = res[0]
            celltyp = res[1]
            subkeys = res[2]

            if celltyp == self.celltype["lf"] or celltyp == self.celltype["lh"]:
                self.readLfSubkeyList(offset + 8, subkeys, parent)
                self.allocated[offset] = 8 + (subkeys * 8)
            elif celltyp == self.celltype["ri"] or celltyp == self.celltype["li"]:
                self.readRiSubkeyList(offset + 8, subkeys, parent)
                self.allocated[offset] = 8 + (subkeys * 4)

  #            for each subkey :self.celltype["lf"]
  #              Parse_Registry_Tree (subkey offset) 

        except vfsError, e:
            print "Base block read Magic ERROR"
#      Allocated_space [offset] = subkey_list cell_size


    def readRiSubkeyList(self, offset, subkeys, parent):
        try:
            buff = self.hive.read(subkeys * 4)

            unpackfmt = "%d" % subkeys
            unpackfmt += "I"
            res = struct.unpack(unpackfmt, buff)

            for subkeyoffset in res:
                self.parseRegistree(subkeyoffset + self.blocksize, parent)

        except vfsError, e:
            print "Base block read Magic ERROR"

    def readLfSubkeyList(self, offset, subkeys, parent):
        try:
            buff = self.hive.read(subkeys * 8)
            
            fmtsub = subkeys * 2

            unpackfmt = "%d" % fmtsub
            unpackfmt += "I"

            res = struct.unpack(unpackfmt, buff)

            cp = 0
            for subkeyoffset in res:
                if cp % 2 == 0:
                    self.parseRegistree(subkeyoffset + self.blocksize, parent)
                cp = cp + 1
        except vfsError, e:
            print "Base block read Magic ERROR"

#    def parseValueListCell(offset)
#      Allocated_space [offset] = value_list_cell_size
#      for each value 
#          Parse_Key_Value_Cell (value_offset) 

#Parse_Key_Value_Cell (offset)

#      Allocated_space [offset] = value_cell_size
#      if value_data_type <> 0x80!:
#          Allocated_space [value_data_cell_offset] = value_data_cell_size) 

class keyNode(Node):
  def __init__(self, mfso, parent, name, hive, vlist, keyoffset, createdtime):
      Node.__init__(self, name, 0x50, parent, mfso)
      self.timestamp = createdtime
      self.hive = hive
      self.parentnode = parent
#      self.mfso = mfso
      self.hname = name
      self.vlist = vlist
      self.keyoffset = keyoffset
      self.__disown__()

      self.regtype = { 0: "REG_NONE",
                       1: "REG_SZ",
                       2: "REG_EXPAND_SZ",
                       3: "REG_BINARY",
                       4: "REG_DWORD",
                       5: "REG_DWORD_BIG_ENDIAN",
                       6: "REG_LINK",
                       7: "REG_MULTI_SZ",
                       8: "REG_RESOURCE_LIST",
                       9: "REG_FULL_RESOURCE_DESCRIPTOR",
                       10: "REG_RESOURCE_REQUIREMENTS_LIST",
                       11: "REG_QWORD"}
#      self.setFile()
      setattr(self, "fileMapping", self.fileMapping)
      setattr(self, "createdTime", self.createdTime)


  def createdTime(self):
      vt = vtime()
      vt.thisown = False
      epoch = 116444736000000000L
      sec = (self.timestamp - epoch) / 10000000
      t = time.gmtime(sec)
      
      vt.year = t.tm_year
      vt.month = t.tm_mon
      vt.day = t.tm_mday
      vt.hour = t.tm_hour
      vt.min = t.tm_min
      vt.sec = t.tm_sec
      vt.wday = t.tm_wday
      vt.yday = t.tm_yday
      vt.dst = 0

      return vt

  def fileMapping(self, fm):
      fm.push(0, 0x50, self.hive.node(), self.keyoffset)
     
  def _attributes(self):
      attr = VMap()	
      attr.thisown = False
      self.getKeyAttributes(attr)
      self.getValuesAttributes(attr)

      vt = Variant(self.createdTime())
      vt.thisown = False
      attr['created'] = vt
      return attr

  def getKeyAttributes(self, attr):
      vmap = VMap()
      vmap.thisown = False

      try:
          self.hive.seek(self.keyoffset)
          keybuff = self.hive.read(0x50)
      except vfsError, e:
          print "Base block read Magic ERROR"
          
      keystruct = struct.unpack('<IHHQIIIIIIIIIIIIIIIHH', keybuff)
#          name = self.hive.read(keystruct[18])
      vhead = Variant(keystruct[0])
      vhead.thisown = False
      vmap["head"] = vhead

      t = struct.pack('h', keystruct[1])
      mag = t + " (0x" + "%X" % keystruct[1] + ")"

      vmagic = Variant(mag)
      vmagic.thisown = False
      vmap["magic"] = vmagic
      vtype = Variant(keystruct[2])
      vtype.thisown = False
      vmap["type"] = vtype
      # add in static attributes
      #          vtime = Variant(keystruct[3])
      #          vtime.thisown = False
      #          vmap["creation time"] = vtime
      vuk1 = Variant(keystruct[4])
      vuk1.thisown = False
      vmap["Unknown"] = vuk1
      vparentkeyoffset = Variant(keystruct[5])
      vparentkeyoffset.thisown = False
      vmap["Parent key offset"] = vparentkeyoffset
      vskstable = Variant(keystruct[6])
      vskstable.thisown = False
      vmap["Number of subkeys (Stable)"] = vskstable
      vskvolatile = Variant(keystruct[7])
      vskvolatile.thisown = False
      vmap["Number of subkeys (Volatile)"] = vskvolatile
      vsklistoffset = Variant(keystruct[8])
      vsklistoffset.thisown = False
      vmap["Subkey's list offset (Stable)"] = vsklistoffset
      vsklistoffsetvol = Variant(keystruct[9])
      vsklistoffsetvol.thisown = False
      vmap["Subkey's list offset (Volatile)"] = vsklistoffsetvol
      vnvalues = Variant(keystruct[10])
      vnvalues.thisown = False
      vmap["Number of values"] = vnvalues
      vlistoffset = Variant(keystruct[11])
      vlistoffset.thisown = False
      vmap["Value list offset"] = vlistoffset
      vskdesc = Variant(keystruct[12])
      vskdesc.thisown = False
      vmap["Security descriptor offset"] = vskdesc
      vclassoff = Variant(keystruct[13])
      vclassoff.thisown = False
      vmap["Class name offset"] = vclassoff
      vuk2 = Variant(keystruct[14])
      vuk2.thisown = False
      vmap["Unknown2"] = vuk2
      vuk3 = Variant(keystruct[15])
      vuk3.thisown = False
      vmap["Unknown3"] = vuk3
      vuk4 = Variant(keystruct[16])
      vuk4.thisown = False
      vmap["Unknown4"] = vuk4
      vuk5 = Variant(keystruct[17])
      vuk5.thisown = False
      vmap["Unknown5"] = vuk5
      vuk6 = Variant(keystruct[18])
      vuk6.thisown = False
      vmap["Unknown6"] = vuk6
      vkeynamelen = Variant(keystruct[19])
      vkeynamelen.thisown = False
      vmap["Key name length"] = vkeynamelen
      vclassnamelen = Variant(keystruct[20])
      vclassnamelen.thisown = False
      vmap["Class name length"] = vclassnamelen

      if keystruct[20] > 0:
          self.readClassName(keystruct[13] + 0x1000, keystruct[20], vmap)
      if keystruct[12] > 0:
          self.readSecurityDescriptor(keystruct[12] + 0x1000, vmap)
      
      v = Variant(vmap)
      v.thisown = False
      attr["Key attributes"] = v

  def readSecurityDescriptor(self, offset, vmap):
      try:
          self.hive.seek(offset)
          skbuff = self.hive.read(24)
          skstruct = struct.unpack("<IHHIIII", skbuff)

          secmap = VMap()
          secmap.thisown = False

          vhead = Variant(skstruct[0])
          vhead.thisown = False
          secmap["head"] = vhead
          vmagic = Variant(skstruct[1])
          vmagic.thisown = False
          secmap["magic"] = vmagic
          vuk = Variant(skstruct[2])
          vuk.thisown = False
          secmap["Unknown"] = vuk
          vprevsk = Variant(skstruct[3])
          vprevsk.thisown = False
          secmap["Point to previous SK"] = vprevsk
          vnextsk = Variant(skstruct[4])
          vnextsk.thisown = False
          secmap["Point to next SK"] = vnextsk
          vrefcount = Variant(skstruct[5])
          vrefcount.thisown = False
          secmap["Reference count"] = vrefcount
          vsksize = Variant(skstruct[6])
          vsksize.thisown = False
          secmap["Size"] = vsksize

          self.readSKBuffer(secmap, skstruct[6])

          v = Variant(secmap)
          v.thisown = False
          vmap["Security descriptor"] = v

      except vfsError, e:
          print "Base block read Magic ERROR"          

# skstruct = struct.unpack("BBHIIII")
# Security descriptor Offset:
# uchar revision (0x1)
# uchar sbz1 
# ushort control
# uint OffsetOwner in buffer 
# uint OffsetGroup in buffer
# uint OffsetSacl
# uint OffsetDacl
#=============
# var  OwnerSid
# var GroupSid
# var Sacl
# var Dacl

#          cname = self.hive.read(classnamelen)

# http://msdn.microsoft.com/en-us/library/cc230366.aspx

  def readSKBuffer(self, secmap, size):
      try:
          skcontentbuff = self.hive.read(20)
          skstruct = struct.unpack("<BBHIIII", skcontentbuff)
          skmap = VMap()
          skmap.thisown = False
          
          vrev = Variant(skstruct[0])
          vrev.thisown = False
          skmap["Revision"] = vrev
          vsbz = Variant(skstruct[1])
          vsbz.thisown = False
          skmap["SBZ"] = vsbz
          vcontrol = Variant(skstruct[2])
          vcontrol.thisown = False
          skmap["Control"] = vcontrol
          vowneroff = Variant(skstruct[3])
          vowneroff.thisown = False
          skmap["Owner offset"] = vowneroff
          vgroupoff = Variant(skstruct[4])
          vgroupoff.thisown = False
          skmap["Group offset"] = vgroupoff
          vsacloff = Variant(skstruct[5])
          vsacloff.thisown = False
          skmap["SACL offset"] = vsacloff
          vdacloff = Variant(skstruct[6])
          vdacloff.thisown = False
          skmap["DACL offset"] = vdacloff

          skdata = size - 20
          
          #TODO read & parse skdata

          v = Variant(skmap)
          v.thisown = False
          secmap["SK data header"] = v

      except vfsError, e:
          print "Base block read Magic ERROR"

  def readClassName(self, offset, classnamelen, vmap):
      try:
          self.hive.seek(offset)
          head = self.hive.read(4)
          cname = self.hive.read(classnamelen)

          classmap = VMap()
          classmap.thisown = False
          
          vhead = Variant(head)
          vhead.thisown = False
          classmap["head"] = vhead

          vname = Variant(cname)
          vname.thisown = False
          classmap["Name"] = vname

          v = Variant(classmap)
          v.thisown = False
          vmap["Class name"] = v

      except vfsError, e:
          print "Base block read Magic ERROR"

  def getValuesAttributes(self, attr):
      if self.vlist != None:
          for val in self.vlist:
              vk = self.readVkRecord(val + 0x1000, attr);

  def readVkRecord(self, offset, attr):
      try:
          self.hive.seek(offset)
          vbuff = self.hive.read(24)
      except vfsError, e:
          print "Base block read Magic ERROR"

      vstruct = struct.unpack('<IHHHHIIHH', vbuff)

      if vstruct[2] == 0:
          name = "Default"
      else:
          try:
              name = self.hive.read(vstruct[2])
          except vfsError, e:
              print "Base block read Magic ERROR"

      vmap = VMap()
      vmap.thisown = False

      voffset = Variant(offset)
      voffset.thisown = False
      vmap["offset"] = voffset

      vhead = Variant(vstruct[0])
      vhead.thisown = False
      vmap["head"] = vhead
      vmagic = Variant(vstruct[1])
      vmagic.thisown = False
      vmap["magic"] = vmagic

      vnamelen = Variant(vstruct[2])
      vnamelen.thisown = False
      vmap["Name length"] = vnamelen

      vdatalen_low = Variant(vstruct[3])
      vdatalen_low.thisown = False
      vmap["Data length"] = vdatalen_low

      vdatalen_high = Variant(vstruct[4])
      vdatalen_high.thisown = False
      vmap["Contains data"] = vdatalen_high

#      if vstruct[6] == 0x1:
#          d = binascii.b2a_uu(vstruct[5])
#          d = vstruct[5]
#      else:
      #d = "0x%.2x" % vstruct[5]
#      d = binascii.hexlify(vstruct[5])
#      d = vstruct[5]

      if vstruct[3] <= 4:
          buf = vbuff[12:15]#vstruct[5]
      else:
          buf = self.getData(vstruct[5] + 0x1000, vstruct[3])

      d = self.convertData(buf, vstruct[6])

      vdata = Variant(d)
      vdata.thisown = False
      vmap["Data"] = vdata

      if vstruct[6] <= 11:
          t = self.regtype[vstruct[6]]
      else:
          t = "Unknown"

      vtype = Variant(t)
      vtype.thisown = False
      vmap["Type"] = vtype

      vflags = Variant(vstruct[7])
      vflags.thisown = False
      vmap["Flags"] = vflags

      vuk = Variant(vstruct[8])
      vuk.thisown = False
      vmap["Unknown"] = vuk

      v = Variant(vmap)
      v.thisown = False

      name += " = "
      name += d

      attr[name] = v


  def getData(self, offset, datalen):
      try:
          self.hive.seek(offset + 4)
          vbuff = self.hive.read(datalen)
          return vbuff
      except vfsError, e:
          print "Base block read Magic ERROR"
      

  def convertData(self, buff, datatype):
      s = ""
      if datatype == 0x1:
          for b in buff:
              if b >= "\x20" and b <= "\x7e":
                  s += b
      else:
          s += "0x"
          pos = str(len(buff)) + 'B'
          bu = struct.unpack(pos, buff)
          for byte in bu:
              s += "%.2x" % byte
      return s


class hbinNode(Node):
  def __init__(self, mfso, parent, name, hive, size, voffset):
      Node.__init__(self, name, size, parent, mfso)
      self.hive = hive
      self.parentnode = parent
      self.hsize = size
      self.voffset = voffset
      self.__disown__()
      self.setFile()
      setattr(self, "fileMapping", self.fileMapping)

  def fileMapping(self, fm):
      fm.push(0, self.hsize, self.hive.node(), self.voffset)


class unallocatedNode(Node):
  def __init__(self, mfso, parent, name, hive, ssize, voffset):
      Node.__init__(self, name, ssize, parent, mfso)
      self.hive = hive
      self.parentnode = parent
      self.voffset = voffset
      self.hsize = size
      self.__disown__()
      self.setFile()
      setattr(self, "fileMapping", self.fileMapping)

  def fileMapping(self, fm):
      fm.push(0, self.hsize, self.hive.node(), self.voffset)


class fullUnallocatedNode(Node):
  def __init__(self, mfso, parent, name, hive, unallocatedlist):
      self.unallocated = unallocatedlist
      ssize = self.getTotalSize()
      Node.__init__(self, name, ssize, parent, mfso)
      self.hive = hive
      self.parentnode = parent
      self.__disown__()
      self.setFile()
      setattr(self, "fileMapping", self.fileMapping)

  def getTotalSize(self):
      ssize = 0
      unallocoffsets = self.unallocated.keys()
      for off in unallocoffsets:
          ssize += self.unallocated[off]

      return ssize

  def fileMapping(self, fm):
      current = 0
      unallocoffsets = self.unallocated.keys()
      unallocoffsets.sort()

      for off in unallocoffsets:
          fm.push(current, self.unallocated[off], self.hive.node(), off)
          current += self.unallocated[off]


      



