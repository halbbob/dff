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

from struct import unpack

from api.vfs import *
from api.module.module import *
from api.env.libenv import *
from api.variant.libvariant import Variant
from api.vfs.libvfs import *

class SpareNode(Node):
   def __init__(self, mfso, parent, name, pageSize = 512, spareSize = 16, lparent = None, invert = False):
     self.invert = invert
     if not self.invert:
       self.ssize = parent.size() - ((parent.size() / (pageSize + spareSize)) * spareSize)
     else:
       self.ssize = ((parent.size() / (pageSize + spareSize)) * spareSize)
     Node.__init__(self, name, self.ssize, lparent, mfso)
     self.setFile()
     self.__disown__()
     self.nparent = parent
     self.pageSize = pageSize
     self.spareSize = spareSize
     setattr(self, "fileMapping", self.fileMapping)
     setattr(self, "extendedAttributes", self.extendedAttributes)

   def fileMapping(self, fm):
      fm.thisown = False
      voffset = 0
      offset = 0
      if not self.invert: #XXX faire 2 node avec le clean + la spare a part ? 
        while voffset < self.ssize:
          fm.push(voffset, self.pageSize, self.nparent, offset)
          offset += (self.spareSize + self.pageSize)
          voffset  += self.pageSize
      if self.invert:
        voffset = 0
        offset = self.pageSize
	while voffset < self.ssize:
	  fm.push(voffset, self.spareSize, self.nparent, offset)
	  offset += (self.spareSize + self.pageSize)
          voffset += self.spareSize 

   def extendedAttributes(self, attr):
      attr.thisown = False
      ps = Variant(self.pageSize)
      ps.thisown = False
      attr.push("page size", ps)
      sps = Variant(self.spareSize)
      sps.thisown = False
      attr.push("spare size", sps)

class Spare(mfso):
   def __init__(self):
      mfso.__init__(self, "spare")
      self.name = "spare"
      self.__disown__()
 
   def start(self, args):
      self.parent = args.get_node("node")
      self.spareSize = args.get_int("spare-size")
      self.pageSize = args.get_int("page-size")
      try :
        self.invert = args.get_bool("invert")
      except KeyError:
        self.invert = False
      if self.pageSize == None or self.pageSize < 0:
        self.pageSize = 512
      if self.spareSize == None or self.spareSize == -1:
        self.spareSize = 16
      self.nosparenode = SpareNode(self, self.parent, "no-spare", self.pageSize, self.spareSize, None, False) 
      if self.invert: 
        self.sparenode = SpareNode(self, self.parent, "spare", self.pageSize, self.spareSize, self.parent, True)  
      self.registerTree(self.parent, self.nosparenode)	

class spare(Module):
  """Recreate a dump without spare area. 
This could be usefull for recovering more data when carving a dump with slack, 
or before applying a file system reconstruction modules."""
  def __init__(self):
     Module.__init__(self, 'spare', Spare)
     self.conf.add("node", "node", False, "Delete spare of this node.")
     self.conf.add("spare-size", "int", False, "size of a nand spare")
     self.conf.add_const("spare-size", 16)
     self.conf.add("page-size", "int", False, "size of a nand page")
     self.conf.add_const("page-size", 512)
     self.conf.add("invert", "bool", True, "Create a spare only node")
     self.tags = "Node"
