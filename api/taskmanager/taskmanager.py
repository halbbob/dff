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
#  Solal J. <sja@digital-forensic.org>
#

from api.events.libevents import EventHandler
from api.taskmanager.scheduler import sched 
from api.taskmanager.processus import *
from api.types.libtypes import Variant, VMap, typeId, Argument, Parameter, ConfigManager
from api.loader import *
from api.exceptions.libexceptions import *
import threading

class TaskManager():
  class __TaskManager(EventHandler):
    def __init__(self):
      EventHandler.__init__(self)
      self.loader = loader.loader()
      self.sched = sched
      self.lprocessus = []
      self.npid = 0
      self.VFS = VFS.Get()
      self.VFS.connection(self)
      self.modPP = []
      self.configManager = ConfigManager.Get()

    def addPostProcess(self, mod, args = None, exec_flags = None):
       self.modPP += [( mod, args, exec_flags)]

    def removePostProcess(self, mod, args = None, exec_flags = None):
       self.modPP.remove( [( mod, args, exec_flags)] )

    def createProcessNode(self, mod, args, exec_flags, node):
       if node.isCompatibleModule(mod) or ("generic" in self.loader.modules[mod].flags):
	 config = self.configManager.configByName(mod)	
         if args == None:
           args = {}
         if exec_flags == None:
           exec_flags = ["console", "thread"]
         args["file"] = node
         arg = config.generate(args)
         self.add(mod, arg, exec_flags)

    def postProcess(self, node, recursive = False):
      for (mod, args, exec_flags) in self.modPP:
        self.createProcessNode(mod, args, exec_flags, node)
        if node.hasChildren():
	  childrens = node.children() 
 	  for child in childrens:
	    self.postProcess(child, True)      

    def Event(self, e):
      if e != None and e.value != None:
        self.postProcess(e.value.value(), True) 

    def add(self, cmd, args, exec_flags):
      mod = self.loader.modules[cmd] 
      proc = None
      if "single" in mod.flags:
         for p in self.lprocessus:
           if p.mod == mod:
	    proc = p
	    proc.timeend = 0
         if not proc:
           proc = Processus(mod, self.npid, None, exec_flags)
           self.lprocessus.append(proc)
           self.npid += 1
      else:
        proc = Processus(mod, self.npid, None, exec_flags)
        self.lprocessus.append(proc)
        self.npid += 1
      if not "thread" in exec_flags:
        try :
          if "gui" in proc.mod.flags and not "console" in proc.mod.flags:
            print "This script is gui only"
	    self.lprocessus.remove(proc)
	    proc.event.set()
	    return proc
        except AttributeError:
	    pass
      sched.enqueue((proc, args))
      return proc
  __instance = None

    
  def __init__(self):
    if TaskManager.__instance is None:
       TaskManager.__instance = TaskManager.__TaskManager()

  def __setattr__(self, attr, value):
	setattr(self.__instance, attr, value)

  def __getattr__(self, attr):
	return getattr(self.__instance, attr) 

  def add(self, cmd, args, exec_flags):
       return self.__instance.add(cmd, args, exec_flags)
