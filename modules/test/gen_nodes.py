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

__dff_module_gen_nodes_version__ = "1.0.0"

from struct import unpack

from api.vfs import *
from api.module.module import *
from api.vfs.libvfs import *
from modules.fs.spare import SpareNode

from api.types.libtypes import Variant, VMap, Parameter, Argument, typeId
from api.vfs.libvfs import AttributesHandler
from api.vfs.vfs import vfs
#
#class CutNode(Node):
   #def __init__(self, mfso, parent, name, startOff, size):
     #self.startOff = startOff
     #self.ssize = size
     #self.pparent = parent
     #if self.ssize == None or self.ssize == 0 or self.ssize < 0:
	#self.ssize = parent.size() - startOff 
     #Node.__init__(self, name + "-" + hex(startOff), self.ssize, None, mfso)
     #self.__disown__()
     #self.name = name
#
   #def fileMapping(self, fm):
     #fm.push(0, self.ssize, self.pparent, self.startOff) 
     # 
   #def _attributes(self):
      #attr = VMap()
      #attr.thisown = False
      #nstart = Variant(self.startOff)
      #nstart.thisown = False
      #attr["start offset"] = nstart
      #return attr
 

class GenNodes(mfso):
    def __init__(self):
       mfso.__init__(self, "GenNodes")
       self.name = "GenNodes"
       self.__disown__()

    def start(self, args):
       self.parent = args["parent"].value()
       if args.has_key("count"):
           self.count = args["count"].value()
       else:
           self.count = 50000
       #self.start = args["start_offset"].value()
       #self.number_of_nodes = args["number_of_nodes"].value()
       self.root = Node("node-test")
       self.__disown__()
       for x in xrange(0, self.count):
	  xnode = Node(str(x), 0, self.root, self)
	  if (x % 10000) == 0:
		print "have create " + str(x) + " nodes"
	  xnode.setDir()
	  xnode.__disown__()
       self.registerTree(self.parent, self.root) 


class gen_nodes(Module): 
  """This modules permit to test the framework by generating a large amount of nodes."""
  def __init__(self):
    Module.__init__(self, "gen_nodes", GenNodes)
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Node, 
	                   "name": "parent", 
	                   "description": "files or folders will be added as child(ren) of this node or as the root node by default",
                           "parameters": {"type": Parameter.Editable,
                                          "predefined": [vfs().getnode("/")]}
                          })
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.UInt64,
                           "name": "count",
                           "description": "number of nodes to create",
                           "parameters:": {"type": Parameter.Editable,
                                           "predefined": [1000, 5000, 10000, 25000, 50000, 70000, 100000, 500000, 1000000, 2**64-1]}
                           })
 
    #self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.UInt64,
                           #"name": "start_offset",
                           #"description": "Address start of the new node"
                           #})

    self.tags = "Node"
