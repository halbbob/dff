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
#  Solal Jacob < sja@arxsys.fr>
#

from PyQt4 import QtCore, QtGui, Qt
from PyQt4.QtCore import Qt, QSize, QString, SIGNAL, QThread, SLOT, QSignalMapper
from PyQt4.QtGui import QPushButton, QLabel, QWidget, QHBoxLayout, QVBoxLayout, QScrollArea, QIcon, QTableWidget, QTableWidgetItem, QComboBox, QInputDialog, QLineEdit, QSplitter, QMessageBox

from struct import unpack

from api.vfs import vfs 
from api.module.module import *
from api.env.libenv import *
from api.variant.libvariant import Variant
from api.vfs.libvfs import *
from modules.fs.spare import SpareNode
from K800i import *
import sys

class K800IRec(QWidget, mfso):
    def __init__(self):
       mfso.__init__(self, "K800i-Recover")
       self.name = "K800i-Recover"
       self.icon = None
       self.__disown__()

    def start(self, args):
       self.vfs = vfs.vfs()
       self.dumpnumber = 1
       self.nor = args.get_node('nor')
       self.nand = args.get_node('nand')
       self.spareSize = args.get_int("spare-size")
       self.pageSize = args.get_int("page-size")
       if self.pageSize == None or self.pageSize < 0:
         self.pageSize = 512
       if self.spareSize == None or self.spareSize == -1:
         self.spareSize = 16

       self.k800n = Node("k800-base")
       self.k800n.__disown__()
       self.boot = SEBootBlock(self.nor, self.pageSize) 
       self.blockSize = self.boot.blockSize
       self.nandClean = SpareNode(self,  self.nand, "nandfs", self.pageSize, self.spareSize, self.k800n)
       self.norFs = NorFs(self, self.k800n,  self.nor, "norfs", self.boot)
       self.fullFs = FullFs(self, self.k800n, self.norFs, self.nandClean, "fullfs", self.boot)
       self.gdfs = GDFS(self, self.k800n, self.nor, "gdfs", self.boot)
       self.firmware = Firmware(self, self.k800n,  self.nor, "firmware", self.boot.norfsoffset)

       self.tables = Tables(self.fullFs, self.blockSize)
       self.registerTree(self.nand, self.k800n)
 
    def createDump(self):
       text, ok = QInputDialog.getText(self, "Create dump", "dump name:", QLineEdit.Normal, "k800-restore-" + str(self.dumpnumber)) 
       if ok and text != "":
         if  (self.vfs.getnode(self.nand.absolute() + "/" + str(text)) == None):  
           self.dumpnumber += 1
           newroot = Node(str(text))
	   newroot.__disown__()
	   for id in range(0, len(self.tables.tablesIdWriteMap) - 1):
             write = int(str(self.gtable.cellWidget(id, 0).currentText()), 16)
             self.tables.map[id] = self.tables.tablesIdWriteMap[id][write]
           virtual = VirtualMap(self, newroot, self.fullFs, self.tables, "virtual", self.blockSize)
           separt = SEPartitionBlock(virtual, self.boot.partitionblock, self.blockSize)
           self.createPart(separt, newroot, virtual)
           self.registerTree(self.nand, newroot) 
         else :
          box = QMessageBox(QMessageBox.Warning, "Error", "Error node already exists", QMessageBox.NoButton, self)
          box.exec_()
          self.createDump()

    def createPart(self, separt, newroot, virtual):
      for part in separt.partTable:
       if part.start > 0:
         p = Partition(self, newroot, virtual, part, self.blockSize)

    def g_display(self):
      QWidget.__init__(self, None)
      self.layout = QVBoxLayout(self)
      self.hlayout = QSplitter(self)
      self.layout.insertWidget(0, self.hlayout)
      self.layout.setStretchFactor(self.hlayout, 1)
      self.gTable()
      self.viewTable()

      self.button = QPushButton("&Create dump")
      self.connect(self.button, SIGNAL("clicked()"), self.createDump)
      self.layout.addWidget(self.button)
     	

    def viewTable(self):
      self.vtable = QTableWidget() 
      self.vtable.setColumnCount(20)	
      self.vtable.setRowCount(48)
      self.hlayout.addWidget(self.vtable)
 
    def viewTableUpdate(self, id):
      write = int(str(self.gtable.cellWidget(id, 0).currentText()), 16) 
      t = self.tables.tablesIdWriteMap[id][write]
      l = t.blockList
      for x in xrange(0, len(t.blockList[0])):
        block = t.blockList[0][x]
        c = ((x) % 20) 
        r = ((x) / 20) 
        item = QTableWidgetItem(QString(hex(block))) 
        tipBlock = (id * 960) + x
        item.setToolTip(QString(hex(tipBlock)))
        item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
        self.vtable.setItem(r ,c,  item)
     

    def gTable(self):
      self.gtable = QTableWidget()
      self.gtable.setColumnCount(1)	
      self.gtable.setRowCount(len(self.tables.tablesIdWriteMap))
      self.gtable.setHorizontalHeaderItem(0, QTableWidgetItem(QString("version")))
      self.hlayout.addWidget(self.gtable)
      self.sigMapper = QSignalMapper(self)
      for id in self.tables.tablesIdWriteMap:
         wlist = self.tables.tablesIdWriteMap[id]
         cbox = QComboBox(self.gtable)
         self.connect(cbox, SIGNAL("activated(QString)"), self.sigMapper, SLOT("map()"))
         self.sigMapper.setMapping(cbox, id)
         l = [] 
         for write in wlist:
           l.append(write)
         l.sort()
         l.reverse()
         for write in l:
	   cbox.addItem(QString(hex(write))) 
	 self.gtable.setCellWidget(id, 0, cbox)
	 self.gtable.setVerticalHeaderItem(id, QTableWidgetItem(QString(hex(id))))
      self.connect(self.sigMapper, SIGNAL("mapped(int)"),  self.viewTableUpdate) 
      self.gtable.setMaximumWidth(self.gtable.columnWidth(0) + self.gtable.verticalHeader().sectionSize(0) + 30)  
 
    def updateWidget(self):
       pass 

class K800iRecover(Module):
  """This modules give access to K800i block-versioning table and permit to generate virtual mapping and partitions according to the choosen table.
     By choosing different table you could come back to previous version of the filesystem and recover deleted files"""
  def __init__(self):
    Module.__init__(self, "K800i-Recover", K800IRec)
    self.conf.add("nor", "node", False, "K800i nor dump")
    self.conf.add("nand", "node", False, "K800i nand dump")
    self.conf.add("spare-size", "int", True, "Size of nand spare")
    self.conf.add_const("spare-size", 16)
    self.conf.add("page-size", "int", True, "Size of nand page")
    self.conf.add_const("page-size", 512)
    self.tags = "Mobile"
