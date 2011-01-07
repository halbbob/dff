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

from api.taskmanager.scheduler import sched 
from api.taskmanager.processus import *
from api.env import *
from api.loader import *
from api.exceptions.libexceptions import *
import threading

class TaskManager:
  class __TaskManager():
    def __init__(self):
      self.loader = loader.loader()
      self.sched = sched
      self.lprocessus = []
      self.npid = 0
      self.env = env.env() 

    def add(self, cmd, args, exec_flags):
      task = self.loader.modules[cmd] 
      proc = Processus(task, self.npid, args, exec_flags)
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
      sched.enqueue(proc)
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
