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

from api.module.module import *
from api.vfs.libvfs import *
from api.taskmanager.scheduler import *
from api.types import libtypes
from api.types.libtypes import *
from api.vfs import *
from ui.console.utils import VariantTreePrinter
import threading

import time

class Processus(Script):
  def __init__(self, mod, pid, args, exec_flags):
    self.vfs = vfs.vfs()
    self.mod = mod
    self.inst = mod.create()
    self.exec_flags = exec_flags
    self.state = "wait"
    self.pid =  pid 
    self.args = args
    self.stream = Queue()
    self.event = threading.Event()
    self.vtreeprinter = VariantTreePrinter()
    self.timestart = 0
    self.timeend = 0
    self.streamOut = None

  def launch(self, args):
    self.state = "exec"
    self.timestart = time.time()
    try :
      self.args = args 
      args.thisown = False 
      self.start(args) 
      try :
        if "gui" in self.exec_flags:
          if "gui" in self.mod.flags:
             for func in sched.event_func["add_qwidget"]:
	        func(self)
	if "console" in self.exec_flags:
	  if "console" in self.mod.flags:
		self.c_display()  
      except AttributeError:
	pass	
    except :
	 error = sys.exc_info()
         self.error(error)
    self.error()
    self.event.set()
    if not "thread" in self.exec_flags:
	self.result()

  def result(self):
    if self.res and len(self.res):
      buff = self.vtreeprinter.fillMap(0, self.res)
      print buff

  def error(self, trace = None):
    if trace:
	 err_type, err_value, err_traceback = trace
	 res = "\n\nWhat:\n"
         res +=  "----------\n"
         err_typeval = traceback.format_exception_only(err_type, err_value)
         for err in err_typeval:
           res += err
         res += "\nWhere:\n"
         res += "-----------\n"
	 err_trace =  traceback.format_tb(err_traceback)
         for err in err_trace:
           res += err
         print res
         verr = Variant(res)
         verr.thisown = False
         self.res["error"] = verr
         self.state = "fail"
         return
    if "gui" in self.exec_flags and "gui" in self.mod.flags:
      self.state = "wait"
    else:
      self.timeend = time.time()
      self.state = "finish"

  def __getattr__(self, attr):
     return  getattr(self.inst, attr)
