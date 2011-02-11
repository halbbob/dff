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
#  Romain Bertholon < rbe@arxsys.fr>
#

from struct import unpack

from api.vfs import *
from api.module.module import *
from api.types.libtypes import Variant, VMap, Argument, Parameter, typeId
from api.vfs.libvfs import *

class MergeNode(Node):
   def __init__(self, name, size, parent, mfso, files):
      Node.__init__(self, name, size, parent, mfso)
      self.files = files
      self.__disown__()

   def fileMapping(self, fm):
      offset = 0
      for f in self.files:
         node = f.value()
         print offset, node.size(), node.absolute()
         fm.push(offset, node.size(), node, 0)
         offset += node.size()
      
   def _attributes(self):
      attr = VMap()
      attr.thisown = False
      i = 1
      for f in self.files:
         fsize = Variant(f.value().size())
         fname = Variant(f.value().name())
         fsize.thisown = False
         fname.thisown = False
         keyname = "file name " + str(i)
         keysize = "file size " + str(i) 
         attr[keyname] = fname
         attr[keysize] = fsize
      return attr 

#      fatstart = Variant(self.partTable.start)
#      fatstart.thisown = False
#      attr.push("partition start", fatstart)
#      blocksize = Variant(self.partTable.blocksize)
#      blocksize.thisown = False
#      attr.push("blocksize", blocksize)
#      size = Variant(self.partTable.size)
#      size.thisown = False
#      attr.push("size in block", size)
 

class MERGE(mfso):
    def __init__(self):
       mfso.__init__(self, "merge")
       self.__disown__()

    def start(self, args):
       self.files = args['files'].value()
       if args.has_key("output"):
          name = args["output"]
       else:
          name = self.files[0].value().name() + "..." + self.files[len(self.files) - 1].value().name()
       if args.has_key("parent"):
          parent = args["parent"].value()
       else:
          parent = self.files[0].value().parent()
       size = 0
       for f in self.files:
          size += f.value().size()
       print size
       self.merge_node = MergeNode(name, size, None, self, self.files)
       self.merge_node.__disown__()
       self.registerTree(parent, self.merge_node)


class merge(Module):
  """This module is designed to concat 2 files."""
  def __init__(self):
    Module.__init__(self, "merge", MERGE)
    self.conf.addArgument({"input": Argument.Required|Argument.List|typeId.Node,
                           "name": "files",
                           "description": "these files will be concatenated in the order they are provided",
                           "parameters": {"type": Parameter.Editable,
                                          "minimum": 2,
                                          "maximum": 10}
                           })
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.String,
                           "name": "output",
                           "description": "the name of file corresponding to the concatenation"
                           })
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Node,
                           "name": "parent",
                           "description": "parent of the resulting output file (default will be basefile)"
                           })
    self.tags = "Node"
