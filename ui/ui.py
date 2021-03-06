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
#  Frederic Baguelin <fba@digital-forensic.org>
#  Solal Jacob <sja@digital-forensic.org>

import sys
import os
import getopt
from api.loader.loader import loader 
from console.console import console
from gui.gui import *
from redirect import RedirectIO

from conf import Conf

class ui():  
  def __init__(self, type, debug = False, verbosity = 0):
   self.debug = debug
   self.type = type
   self.verbosity = verbosity
   RedirectIO(None, self.debug)
   self.modPath = sys.path[0] + "/modules/"

  def launch(self):
   if self.type == "gui":
     self.g = gui(self.debug)
     try:
       self.c
       self.g.launch()
     except AttributeError:
       self.g.launch(self.modPath)
   if self.type == "console":
     try :
      self.c.cmdloop()
     except AttributeError:
       loader().do_load(self.modPath)
       self.c = console(DEBUG = self.debug, VERBOSITY = self.verbosity)
       self.c.cmdloop()

  def cmd(self, command, wait=False):
    try :
     self.c.onecmd(command)
    except AttributeError:
     loader().do_load(self.modPath)
     self.c = console(DEBUG = self.debug, VERBOSITY = self.verbosity)
     self.c.onecmd(command, wait)

class usage():
   PROGRAM_USAGE = """DFF\nDigital Forensic Framework\n
Usage: """ + sys.argv[0] + """ [options]
Options:
  -v      --version                  display current version
  -g      --graphical                launch graphical interface
  -t      --test=NAME	             start a specific test
  -l      --language=LANG            use LANG as interface language
  -h      --help                     display this help message
  -d      --debug                    redirect IO to system console
          --verbosity=LEVEL          set verbosity level when debugging [0-3]
  -c      --config=FILEPATH          use config file from FILEPATH
"""
   VERSION = "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}"

   def __init__(self, argv):
     self.argv = argv
     self.graphical = 0
     self.test = ''
     self.confPath = ''
     self.debug = False
     self.verbosity = 0
     self.batch = None
# Configuration
     self.main()
     self.conf = Conf(self.confPath)
  

   def main(self):
    """Check command line argument"""
    try:
        opts, args = getopt.getopt(self.argv, "vgdht:l:c:b:", [ "version", "graphical",  "debug", "help", "test=", "language=", "verbosity=", "config=", "batch="])
    except getopt.GetoptError:
        self.usage()
    for opt, arg in opts:
        if opt in ("-h", "--help"):
          self.usage()
        elif opt in ("-g", "--graphical"):
          self.graphical = 1
        elif opt in ("-t", "--test"):
          self.test = arg
        elif opt in ("-l", "--language"):
          self.conf.setLanguage(arg[:2])
        elif opt in ("-v", "--version"):
          print "dff version " + self.VERSION
          sys.exit(1)
        elif opt in ("-d", "--debug"):
          self.debug = True
        elif opt == "--verbosity":
          self.verbosity = int(arg)
        elif opt in ("-c", "--config"):
          self.confPath = str(arg)
	elif opt in  ("-b", "--batch"):
	  self.batch = str(arg)
    return

   def usage(self):
    """Show usage"""
    print self.PROGRAM_USAGE
    sys.exit(2)

