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

__dff_module_jobs_version__ = "1.0.0"

from api.vfs import *
from api.module.module import *
from api.taskmanager.taskmanager import *
from api.module.script import *
from api.types.libtypes import Variant

class JOBS(Script):
  def __init__(self):
    Script.__init__(self, "jobs")
    self.tm = TaskManager()

  def start(self, args):
    buff = "pid\tname\tstate\tinfo\n"
    self.lprocessus = self.tm.lprocessus
    for proc in self.lprocessus:
      if proc.name != "jobs":
        buff += "[" + str(proc.pid) + "]\t" + proc.name + "\t" + proc.state + "\t" + str(proc.stateinfo) + "\n"
    if not buff:
	buff += "No processus launched yet !"
    r = Variant(buff)
    r.thisown = False
    self.res["result"] = r


class jobs(Module):
  """Display launched processus"""
  def __init__(self):
   Module.__init__(self, "jobs", JOBS)
   self.tags = "builtins"
   self.flags = ["console"]
