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
from api.exceptions.libexceptions import *
from api.types.libtypes import Variant, Argument, typeId

class CD(Script):
  def __init__(self):
    Script.__init__(self, "cd")

  def start(self, args):
    node = args["dir"].value()
    if not node:
      val = Variant("Can't find file")
      val.thisown = False
      self.res["error"] = val
      return
    if not node.hasChildren():
      val = Variant("Can't change current directory on file")
      val.thisown = False
      self.res["error"] = val
      return 
    self.vfs.setcwd(node)
    val = Variant("change path to " + str(node.absolute()))
    val.thisown = False
    self.res["result"] = val


class cd(Module):
  """Change current directory"""
  def __init__(self):
   Module.__init__(self, "cd", CD)
   self.conf.addArgument({"name": "dir",
                          "description": "Directory to go in",
                          "input": Argument.Single|Argument.Optional|typeId.Node})
   self.tags = "builtins"
