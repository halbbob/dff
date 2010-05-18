# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2010 ArxSys
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

from api.vfs import *
from api.module.module import *
from api.module.script import *

class LS(Script):
  def __init__(self) :
    Script.__init__(self, "ls")
    self.vfs = vfs.vfs()

  def start(self, args):
    self.node = args.get_node('node')
    self.long = args.get_bool('long')
    self.rec = args.get_bool('recursive')
    if self.node == None:
      self.node = self.vfs.getcwd()
    self.res = self.launch()

  def launch(self):
     if self.rec:
       self.recurse(self.node)
     else :
       self.ls(self.node)

  def recurse(self, cur_node):
    if cur_node.hasChildren():
      self.ls(cur_node)
    next = cur_node.getChildren()
    for next_node in next:
      if next_node.hasChildren():
        self.recurse(next_node)

  def ls(self, node):
     buff = ""
     next = node.getChildren()
     for n in next:
       print self.display_node(n)
       #self.display_node(n)

  def display_node(self, node):
    if self.long:
      return self.display_node_long(node)
    else:
      return self.display_node_simple(node)

  def display_node_long(self, node):
    buff = node.getPath() + node.getName()
    if not node.hasChildren():
      buff += "/" 
    #if node.is_file:
    #  buff += '\t' + str(node.attr.size)
    return buff

  def display_node_simple(self, node):
    buff = ''	
    buff = node.getName()
    if node.hasChildren():
     buff += "/"
    return buff

class ls(Module):
  """List file and directory"""
  def __init__(self):
   Module.__init__(self, "ls", LS)
   self.conf.add("node", "node", True, "Directory to list")
   self.conf.add("long", "bool", True, "Display size of files")
   self.conf.add("recursive", "bool", True, "Recurse in sub-directory")
   self.tags = "builtins"
