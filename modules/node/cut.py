# DFF -- An Open Source Digital Forensics Framework
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
#  Solal Jacob < sja@arxsys.fr>
#

from struct import unpack

from api.vfs import *
from api.module.module import *
from api.env.libenv import *
from api.variant.libvariant import Variant, VMap
from api.vfs.libvfs import *
from modules.fs.spare import SpareNode

class CutNode(Node):
   def __init__(self, mfso, parent, name, startOff, size):
     self.startOff = startOff
     self.ssize = size
     self.pparent = parent
     if self.ssize == None or self.ssize == 0 or self.ssize < 0:
	self.ssize = parent.size() - startOff 
     Node.__init__(self, name + "-" + hex(startOff), self.ssize, None, mfso)
     self.__disown__()
     self.name = name
     setattr(self, "extendedAttributes", self.extendedAttributes)
     setattr(self, "fileMapping", self.fileMapping)

   def fileMapping(self, fm):
     fm.push(0, self.ssize, self.pparent, self.startOff) 
      
   def extendedAttributes(self, attr):
      attr.thisown = False
      nstart = Variant(self.startOff)
      nstart.thisown = False
      attr.push("start offset", nstart) 
 

class Cut(mfso):
    def __init__(self):
       mfso.__init__(self, "Cut")
       self.name = "Cut"
       self.__disown__()

    def start(self, args):
       self._if = args.get_node('in')
       self._of = args.get_string('out')
       self.start = args.get_int("start")
       self.size = args.get_int("size")
       self.nof = CutNode(self, self._if, self._of, self.start, self.size)
       self.nof.__disown__()
       self.registerTree(self._if, self.nof) 


class cut(Module): 
  """This modules allow you to cut a node from a starting offset"""
  def __init__(self):
    Module.__init__(self, "cut", Cut)
    self.conf.add("in", "node", False, "node to cut")
    self.conf.add("out", "string", False, "output node name")
    self.conf.add("start", "int", False, "Start offset of the new node")
    self.conf.add("size", "int", True, "Size of the output node")
    self.tags = "node"
