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
#  Jeremy MOUNIER <jmo@digital-forensic.org>
#

from PyQt4.QtGui import QDockWidget, QAction, QApplication, QTextEdit, QWidget, QHBoxLayout, QTabWidget, QPlainTextEdit
from PyQt4.QtCore import Qt, SIGNAL, QThread, QObject
from ui.redirect import RedirectIO
import os, sys


class CIO(QThread):
  def __init__(self, IOout, fd, sig):
      QThread.__init__(self)
      self.ioOut = IOout
      self.pipe = os.pipe()
      os.close(fd)
      os.dup2(self.pipe[1], fd)   
      self.sig = sig	 

  def run(self):
      while (True):
        try :
  	  buff = os.read(self.pipe[0], 4096)
          self.ioOut.emit(SIGNAL(self.sig), buff)
        except OSError:
	  pass

class STDOut(QPlainTextEdit):
   def __init__(self, parent, debug):
     QPlainTextEdit.__init__(self)
     self.setReadOnly(1)
     self.parent = parent
     self.name = "Output"
     self.debug = debug
     self.sigout = "IOOUTputtext"
     self.connect(self, SIGNAL(self.sigout), self.puttext)
     if sys.__stdout__.fileno() >= 0 and not self.debug:
       self.cioout = CIO(self, sys.__stdout__.fileno(), self.sigout)
       self.cioout.start()

   def puttext(self, text):
     self.insertPlainText(text)

class STDErr(QPlainTextEdit):
   def __init__(self, parent, debug):
     QPlainTextEdit.__init__(self)
     self.setReadOnly(1)
     self.parent = parent
     self.name = "Errors"
     self.debug = debug
     self.sigerr = "IOERRputtext"
     self.connect(self, SIGNAL(self.sigerr), self.puttext)
     if sys.__stderr__.fileno() >= 0 and not self.debug: 
       self.cioerr = CIO(self, sys.__stderr__.fileno(), self.sigerr)
       self.cioerr.start()

   def puttext(self, text):
     self.insertPlainText(text)

