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
from api.types.libtypes import Variant, VMap, Parameter, Argument, typeId
from api.vfs.libvfs import AttributesHandler

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

   def fileMapping(self, fm):
      fm.thisown = False
      voffset = 0
      offset = 0
      if not self.invert:
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

   def _attributes(self):
      attr = VMap()
      attr.thisown = False
      ps = Variant(self.pageSize)
      ps.thisown = False
      attr["page size"] = ps
      sps = Variant(self.spareSize)
      sps.thisown = False
      attr["spare size"] = sps
      return attr	

class Spare(mfso):
   def __init__(self):
      mfso.__init__(self, "spare")
      self.name = "spare"
      self.__disown__()
 
   def start(self, args):
      self.invert = None
      try:
        self.parent = args['node'].value()
      except IndexError:
        return 
      try: 
        self.spareSize = args["spare-size"].value()
      except IndexError:
	self.spareSize = 16
      try:
        self.pageSize = args["page-size"].value()
      except IndexError:
	self.pageSize = 512
      try:
	self.invert = args["dump_spare"]
      except IndexError:
	pass	
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
     self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node,
                            "name": "node",
                            "description": "Delete spare areas in this node"
                            })
     
     self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.UInt16,
                            "name": "spare_size",
                            "description": "Spare size",
                            "parameters": {"type": Parameter.Editable,
                                           "predefined": [16, 8, 24, 32]}
                            })
     
     self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.UInt32,
                            "name": "page_size",
                            "description": "Iterate on each page size",
                            "parameters": {"type": Parameter.Editable,
                                           "predefined": [512, 256, 1024]}
                            })

     self.conf.addArgument({"input": Argument.Empty,
                            "name": "dump_spare",
                            "description": "Create a node with only spares data"
                            })
     self.tags = "Node"
