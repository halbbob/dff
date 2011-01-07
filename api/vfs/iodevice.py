# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2010 ArxSys
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
#  Solal Jacob <sja@digital-forensic.org>
# 

from PyQt4.QtCore import QIODevice 

class IODevice(QIODevice):
   def __init__(self, node):
      super(QIODevice, self).__init__()  	
      self.file = None
      self.node = node    
 
   def open(self, mode = None):
     try :
       self.file = self.node.open()
       self.setOpenMode(QIODevice.ReadOnly | QIODevice.Unbuffered)
       return True
     except AttributeError:
       return False 

   def seek(self, pos):
     n = self.file.seek(pos)
     if n == pos:
       return True
     return False

   def close(self):
      self.file.close() 
      return True  

   def readData(self, size):
      return self.file.read(size)

   def pos(self):
      return long(self.file.tell())

   def isSequential(self):
      return False

   def size(self):
      return long(self.node.size())

   def reset(self):
      self.file.seek(0)
      return True

   def atEnd(self):
      if self.file.tell() >= self.node.size():
	return True
      return False  


