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
#  Romain Bertholon < rbe@arxsys.fr>
#

from struct import unpack

from api.vfs import *
from api.module.module import *
from api.env.libenv import *
from api.variant.libvariant import Variant, VMap
from api.vfs.libvfs import *
from modules.fs.spare import SpareNode

class MergeNode(Node):
   def __init__(self, name, size, parent, mfso, file1, file2):
      Node.__init__(self, name, file1.size() + file2.size(), parent, mfso)
      self.file1 = file1
      self.file2 = file2
      self.__disown__()

   def fileMapping(self, fm):
      fm.push(0, self.file1.size(), self.file1, 0)
      fm.push(self.file1.size(), self.file2.size(), self.file2, 0)
      
   def extendedAttributes(self, attr):
      print "extended attr"
      f1_size = Variant(self.file1.size())
      f2_size = Variant(self.file2.size())
      f1_name = Variant(self.file1.name())
      f2_name = Variant(self.file2.name())
      attr.thisown = False
      f1_size.thisown = False
      f2_size.thisown = False
      f1_name.thisown = False
      f2_name.thisown = False
      attr.push("1st file name", f1_name)
      attr.push("2nd file name", f2_name)
      attr.push("1st file size", f1_size)
      attr.push("2nd file size", f2_size)


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
       self.file1 = args.get_node('file1')
       self.file2 = args.get_node('file2')
       name = self.file1.name() + "-" + self.file2.name()
       size = self.file1.size() + self.file2.size()
       self.merge_node = MergeNode(name, size, None, self, self.file1, self.file2)
       self.merge_node.__disown__()
       self.registerTree(self.file1.parent(), self.merge_node)

class merge(Module):
  """This module is designed to concat 2 files."""
  def __init__(self):
    Module.__init__(self, "merge", MERGE)
    self.conf.add("file1", "node", False, "first file")
    self.conf.add("file2", "node", False, "second file")
    self.tags = "Node"
