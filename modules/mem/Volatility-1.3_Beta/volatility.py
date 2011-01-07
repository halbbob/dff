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

import sys
import os
import forensics.registry as MemoryRegistry

from vmodules import *

from api.vfs import *
from api.module.module import *
from api.module.script import *

from dfwrapper import *
#XXX fix dump options

class Volatility(mfso):
  def __init__(self):
    mfso.__init__(self, "volatility")
    self.__disown__()
    self.name = "volatility"
    self.vfs = vfs.vfs()

  def start(self, args):
    self.node = args.get_node('file')
    try:
      self.meta = args.get_bool("meta")
    except KeyError:
      self.meta = None
    try :
      self.dump = args.get_bool("dump") #XXX dump mem / dump disk !
    except KeyError:
      self.dump = None
    try :
      self.connections = args.get_bool("connection") #XXX dump mem / dump disk !
    except KeyError:
      self.connections = None
    try :
      self.openfiles = args.get_bool("openfiles")
    except KeyError:
      self.openfiles = None
    self.root = Node("volatility")
    self.root.__disown__()
    self.op = op(self.node)
    (self.addr_space, self.symtab, self.types) = load_and_identify_image(self.op, self.op)
    self.proclist = self.pslist()
       

    for proc in self.proclist:
     if self.meta:
       proc.getMeta()
     if self.dump:
       e = proc.dump()
       if e:
        self.res.add_const("error", e)
     if self.openfiles:
       proc.getOpenFiles() 
     if self.connections:
       proc.getConnections() 
     #proc.file.close()
    self.registerTree(self.node, self.root)
 
  def pslist(self):	
    self.all_tasks = process_list(self.addr_space,self.types,self.symtab)
    lproc = []
    for task in self.all_tasks:
      if not self.addr_space.is_valid_address(task):
          continue
      lproc.append(processus(self, task, self.op.filename, self.addr_space, self.types, self.symtab))
    return lproc


class volatility(Module):
  def __init__(self):
   """Analyse a windows-xp ram dump"""
   Module.__init__(self, "volatility", Volatility)
   self.conf.add("file", "node", False, "Dump to analyse")
   self.conf.add("meta", "bool", True, "Generate meta-data for each processus")
   self.conf.add("dump", "bool", True, "Dump processus data content")
   self.conf.add("openfiles", "bool", True, "List opened files per processus")
   self.conf.add("connection", "bool", True, "List opened connection per processus")
   self.tags = "Volatile memory"
