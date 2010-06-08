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
#  Frederic Baguelin <fba@digital-forensic.org>
# 

import os
from api.vfs import *
from api.module.script import *
from api.exceptions.libexceptions import *
from api.module.module import *
import time


class EXTRACT(Script):
  def __init__(self):
    Script.__init__(self, "extract")
    self.vfs = vfs.vfs()
    self.total = 0
    self.current = 0

  def start(self, args):
    self.nodes = args.get_lnode('files')
    self.path = args.get_path('syspath').path
    if self.path[-1] == "/":
      self.path = path[-1:]
      print self.path
    self.rec = args.get_bool('recursive')
    res = ""
    for node in self.nodes:
      if node.hasChildren() and self.rec:
        self.total += self.get_total_to_extract(node)
      else:
        self.total += 1
    for node in self.nodes:
      res += self.launch(node)
    self.res.add_const("result", res)


  def launch(self, node):
    res = ""
    if node.hasChildren():
      if self.rec:
        res += self.recurse(node, "")
      else:
        self.current += 1
        self.stateinfo = str(self.current) + " / " + str(self.total)
        if not os.path.exists(self.path + "/" + node.name()):
          try:
            os.mkdir(self.path + "/" + node.name())
            res += "directory " + node.name() + " created in " + self.path + "\n"
          except OSError:
            res += "extract: Can't create directory " + self.path + node.name() + "\n"
    else:
      res = self.extract(node, "")
    return res


  def get_total_to_extract(self, node):
    total = 0
    next = node.children()

    total += 1
    for cur_node in next:
      if cur_node.hasChildren():
        total += self.get_total_to_extract(cur_node)
      else:
        total += 1
    return total


  def recurse(self, node, vpath):
    res = ""
    if node.hasChildren():
      vpath += "/" + node.name()
      self.current += 1
      self.stateinfo = str(self.current) + " / " + str(self.total)
      if not os.path.exists(self.path + vpath):
        try:
          os.mkdir(self.path + vpath)
          res += "directory " + node.name() + " created in " + self.path + vpath + "\n"
        except OSError:
          res += "extract: Can't create directory " + self.path + vpath + node.name() + "\n"
      next = node.children()
      for cur_node in next:
        if not cur_node.hasChildren():
          res += self.extract(cur_node, vpath)
        else:
          res += self.recurse(cur_node, vpath)
    else:
      res += self.extract(cur_node, vpath)
    return res + "\n"


  def extract(self, node, vpath):
    syspath = self.path + vpath + "/"
    sysname = node.name()
    try:
      self.current += 1
      self.stateinfo = str(self.current) + " / " + str(self.total)
      vfile = node.open()
      sysfile = open(syspath + sysname, 'wb')
      readsize = 8096
      buff = vfile.read(readsize)
      while len(buff):
        sysfile.write(buff)
        buff = vfile.read(readsize)
      vfile.close()
      sysfile.close()
      return "file: " + node.absolute() + " extracted in " + syspath + sysname + "\n"
    except vfsError, e:
      return "extract: Can't open " + node.absolute() + "\n"
    except OSError:
      return "extract: Can't create file " + syspath + "\n"

class extract(Module):
  """Extract file in your operating system file system."""
  def __init__(self):
    Module.__init__(self, "extract", EXTRACT)
    self.conf.add("files", "lnode", False, "Files or directories list to extract.")
    self.conf.add("syspath", "path", False, "Local file system path where to extract files.") 
    self.conf.add("recursive", "bool", True, "Extract recursivly each files in all in sub-directories.")
    self.tags = "process"
