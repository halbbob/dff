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

from api.module.script import Script 
from api.taskmanager.taskmanager import TaskManager
from api.module.module import Module 
from api.types.libtypes import Variant, Argument, typeId, ConfigManager

class POST_PROCESS(Script):
  def __init__(self):
    Script.__init__(self, "post_process")
    self.tm = TaskManager()

  def start(self, args):
    mod = args["module"]
    if mod:
      self.tm.addPostProcess(mod)
    return

class post_process(Module):
  """Process a command on each new file created on the vfs"""
  def __init__(self):
    Module.__init__(self, "post_process", POST_PROCESS)
    self.conf.addArgument({"name":"module",
			   "description": "Module to add to the post processing list",
			   "input" : Argument.Required|Argument.Single|typeId.String}) 	
    self.tags = "builtins"
