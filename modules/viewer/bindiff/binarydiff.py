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

import sys
from api.module.script import *
from api.vfs import *
from api.module.module import *

from PyQt4.QtCore import QSize, SIGNAL
from PyQt4.QtGui import QWidget, QVBoxLayout, QIcon

from BDiff import BDiff

class binDiff(QWidget, Script):
    def __init__(self):
        Script.__init__(self, "bindiff")
        self.type = "bindiff"
        self.icon = ""
        
    def start(self, args) :
        self.args = args

    def c_display(self):
      pass
#        node = self.args.get_node("file")
#	try:
#          nceditor.start(node)
#	except NameError:
#	  print "This functionality is not available on your operating system"	

    def g_display(self):
        QWidget.__init__(self)
        self.vlayout = QVBoxLayout(self)
        self.widget = BDiff(self)
        self.vlayout.addWidget(self.widget)
        node1 = self.args.get_node("file1")
        node2 = self.args.get_node("file2")
        self.name = "binDiff " + str(node1.name()) + " | " + str(node2.name())
        self.widget.init(node1, node2)
        
    def updateWidget(self):
        pass

    def initCallback(self):
        pass 
    
    def refresh(self):
        pass 

class binarydiff(Module):
  def __init__(self):
    Module.__init__(self, "diff", binDiff)
    self.conf.add("file1", "node")
    self.conf.add("file2", "node")
    self.tags = "Viewers"

