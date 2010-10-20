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

from api.magic.filetype import *
from api.vfs import *
from api.env import *
from api.loader import *
from api.module.module import *
from api.module.script import *

class FILEINFO(Script): 
  def __init__(self):
      Script.__init__(self, "fileinfo")
      self.ft = FILETYPE()

  def countFilesAndFolders(self, node):
    children = node.children()
    filessize = 0
    filecount = 0
    dircount = 0
    buff = ""
    for child in children:
      if child.isFile():
        filessize += child.size()
        filecount += 1
      elif child.isDir():
        dircount += 1
    buff += " " + str(filecount) + " files totalizing " + str(filessize) + " bytes\n"
    buff += " " + str(dircount) + " folder(s)\n"
    return buff

  def start(self, args):
    buff = ""
    node = args.get_node("file")
    if node.isFile():
      buff += "File " + node.absolute()
      if node.size() > 0:
        buff += " has content\n"
      else:
        buff += " is empty\n"
      if node.hasChildren():
        buff += "module(s) has (have) been applied"
        childcount = node.childCount()
        if childcount > 0:
          buff += " and added " + str(childcount) + " children at first level:\n"
          buff += self.countFilesAndFolders(node)
        else:
          buff += " and added no children\n"
      else:
        buff += "no module(s) has (have) been applied\n"
      buff += "size: " + str(node.size()) + " \n"
    elif node.isDir():
      buff += "Folder " + node.absolute()
      if node.hasChildren():
        childcount = node.childCount()
        buff += " has " + str(childcount) + " children:\n" 
        buff += self.countFilesAndFolders(node)
      else:
        buff += "is empty\n"
    self.ft.filetype(node)
    try:
      attrs = node.staticAttributes()
      map = attrs.attributes()
      for key, val in map.iteritems():
        buff += key + ": " + str(val) + "\n"
    except IndexError, AttributeError:
      buff += "no static attributes\n"
    try:
      attrs = Attributes()
      attrs.thisown = False
      node.extendedAttributes(attrs)
      map = attrs.attributes()
      for key, val in map.iteritems():
        buff += key + ": " + str(val) + "\n"
    except IndexError, AttributeError:
      buff += "no extended attributes\n"
    try:
      ntimes = node.times()
      buff += "default times:\n"
      for timetype, t in ntimes.iteritems():
        buff += " " + str(timetype) + ": " + str(t.get_time())  + "\n"
    except:
      buff += "no default time recorded\n"
    if node.isFile() == 1:
      n = self.ft.findcompattype(node)
      if len(n):
        buff += "relevant module(s):\n"
        for i in n:
          buff += " " + i + "\n"
    self.res.add_const("result", buff)

class fileinfo(Module):
  """Display file attribute informations. (size, MAC time, ...)"""
  def __init__(self):
    Module.__init__(self, "fileinfo",  FILEINFO)
    self.conf.add("file", "node", False, "File where info is searched.")
    self.tags = "utils"
