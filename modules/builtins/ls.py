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

from api.vfs import *
from api.module.module import *
from api.module.script import *
from api.types.libtypes import typeId, Argument

class LS(Script):
  def __init__(self) :
    Script.__init__(self, "ls")
    self.vfs = vfs.vfs()

  #def start(self, **kwargs):
  #  print dir(self)
  #  self.__dict__.update(kwargs)
  #  print dir(self)


  def start(self, args):
    try:
      self.nodes = list(lambda(node: node.value(), args["nodes"]))
      print self.nodes
    except KeyError:
      self.nodes = self.vfs.getcwd()
    try:
      self.long = args["long"].value():
    except KeyError:
      self.long = False
    try:
      self.rec = args['recursive'].value()
    except KeyError:
      self.rec = False
    self._res = self.launch()



  def launch(self):
    for node in self.nodes:
     if self.rec:
       self.recurse(node)
     else:
       self.ls(node)

  def recurse(self, cur_node):
    if cur_node.hasChildren():
      self.ls(cur_node)
    next = cur_node.children()
    for next_node in next:
      if next_node.hasChildren():
        self.recurse(next_node)

  def ls(self, node):
     buff = ""
     print self.display_node(n)

  def display_node(self, node):
    if self.long:
      return self.display_node_long(node)
    else:
      return self.display_node_simple(node)

  def display_node_long(self, node):
    buff = node.absolute()
    if not node.hasChildren():
      buff += "/"
    if not node.hasChildren():
      buff += '\t' + str(node.size())
    return buff

  def display_node_simple(self, node):
    buff = ''	
    buff = node.name()
    if node.hasChildren():
     buff += "/"
    return buff

class ls(Module):
  """List file and directory"""
  def __init__(self):
   Module.__init__(self, "ls", LS)
   self.conf.addArgument({"name": "nodes",
                          "description": "files to list",
                          "input": Argument.List|Argument.Optional|typeId.Node})
   self.conf.addArgument({"name": "long",
                          "description": "Display more information for each files",
                          "input": Argument.Empty})
   self.conf.addArgument({"name": "recursive",
                          "description": "enables recursion on folders",
                          "input": Argument.Empty)
   self.tags = "builtins"
