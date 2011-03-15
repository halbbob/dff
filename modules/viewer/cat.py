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
#  Solal Jacob <sja@digital-forensic.org>
# 

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *

from api.vfs import *
from api.module.module import *
from api.module.script import *
from api.types.libtypes import Argument, typeId

class CAT(QTextEdit, Script):
  def __init__(self):
    Script.__init__(self, "cat")
    self.vfs = vfs.vfs()
    self.type = "cat"
    self.icon = None
  
  def start(self, args):
    self.args = args
    try:
      self.node = args["file"].value()
      self.cat(self.node)
    except:
      pass

  def g_display(self):
    QTextEdit.__init__(self, None)
    self.setReadOnly(1)
    self.append(QString.fromUtf8(self.buff))

  def updateWidget(self):
	pass

  def cat(self, args):
    file = self.node.open()
    fsize = self.node.size()
    size = 0
    self.buff = ""
    while size < fsize:
      try:
       tmp = file.read(4096)
      except vfsError, e:
        print self.buff
        break
      if len(tmp) == 0:
        print tmp
        break         
      size += len(tmp)
      self.buff += tmp
      print tmp
    file.close()
    if len(self.buff): 
     return self.buff

class cat(Module):
  """Show text file content
ex:cat /myfile.txt"""
  def __init__(self):
    Module.__init__(self, "text", CAT)
    self.conf.addArgument({"name": "file",
                           "description": "Text file to display",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["HTML", "ASCII", "XML", "text"]})
    self.tags = "Viewers"
    self.flags = ["console", "gui"]
    self.icon = ":text"	
