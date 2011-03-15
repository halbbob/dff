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
#  Christophe Malinge <cma@digital-forensic.org>
#  Solal Jacob <sja@digital-forensic.org>
#

from conf import Conf

class history():
  class __history():
    def __init__(self):
      self.conf = Conf()
      self.hist = []
      self.wfile = None
      self.current = 0
      self.load()

    def load(self):
        self.path = self.conf.historyFileFullPath
        if self.wfile:
          self.wfile.close()
        try:
          if not self.conf.noHistoryFile and not self.conf.noFootPrint:
            self.rfile = open(self.path, 'r')
            self.wfile = open(self.path, 'a')
            self.hist = self.rfile.readlines()
            self.rfile.close()
	  self.current = len(self.hist)
        except IOError:
          if not self.conf.noHistoryFile and not self.conf.noFootPrint:
            self.wfile = open(self.path, 'a')
        return

    def getnext(self):
	self.current -= 1
	if self.current < 0:
	  self.current = 0
        try :
	  cmd = self.hist[self.current]
        except IndexError:
	  return None
        return cmd.strip('\n')

    def getprev(self):
	self.current += 1
	if self.current >= len(self.hist):
	  self.current = len(self.hist) - 1
	  return None
 	cmd = self.hist[self.current]
	return cmd.strip('\n')

    def save(self):
        if not self.conf.noHistoryFile and not self.conf.noFootPrint:
          self.wfile.close()

    def add(self, cmd):
        try: 
          self.hist += [ cmd ]
          if not self.conf.noHistoryFile and not self.conf.noFootPrint:
            self.wfile.write(cmd + "\n")
            self.wfile.flush()
        except IOError:
          print "can't write on history" 
        return 

    def clear(self):
        self.hist = []
        if not self.conf.noHistoryFile and not self.conf.noFootPrint:
          self.wfile.close()
          self.wfile = open(self.path, 'w')

  __instance = None

  def __init__(self):
    if history.__instance is None:
       history.__instance = history.__history()

  def __setattr__(self, attr, value):
    setattr(self.__instance, attr, value)

  def __getattr__(self, attr):
    return getattr(self.__instance, attr)
