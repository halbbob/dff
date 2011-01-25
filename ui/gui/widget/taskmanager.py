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


from PyQt4.QtGui import QAction, QApplication, QDockWidget, QIcon,  QHBoxLayout, QPushButton, QTabWidget, QTreeWidget, QTreeWidgetItem, QWidget, QDialog, QGridLayout, QLabel, QComboBox, QMessageBox
from PyQt4.QtCore import QRect, QSize, Qt, SIGNAL

#from api.loader import *
from api.env import *
from api.taskmanager.taskmanager import *

from ui.gui.utils.utils import Utils
#from ui.gui.widget.stdio import IO 

#from ui.redirect import RedirectIO

class Processus(QTreeWidget):
    def __init__(self, parent):
        QTreeWidget.__init__(self, parent)
        self.name = "Task manager"
        self.tm = TaskManager()
        self.initTreeProcess()

    def initTreeProcess(self):
        self.setColumnCount(3)
        headerLabel = [self.tr("PID"), self.tr("Name"),
                       self.tr("State"), self.tr("Info"),
                       self.tr("Exec Time")]
        self.setHeaderLabels(headerLabel)
        self.setAlternatingRowColors(True)
 	self.connect(self, SIGNAL("itemDoubleClicked(QTreeWidgetItem*,int)"), self.procClicked)
	self.procItemDic = dict()
        self.procChildItemDic = dict()

    def procClicked(self, item, column):
	dial = procMB(self, self.__mainWindow, item.text(0))
	dial.exec_()

    def LoadInfoProcess(self):
	lproc = self.tm.lprocessus
	for proc in lproc:
	  try:
	    item = self.procItemDic[proc]
	  except KeyError:
	    item = QTreeWidgetItem(self)
	    self.procItemDic[proc] = item
	    item.setText(0, str(proc.pid))
	    item.setText(1, str(proc.name))
          if item.text(2) != str(proc.state):
            item.setText(2, str(proc.state))
          if item.text(3) != str(proc.stateinfo):
	    item.setText(3, str(proc.stateinfo))
	  if not proc.timeend:
	    ctime = time.time() - proc.timestart 
	    item.setText(4, "%.2d:%.2d:%.2d" % ( (ctime / (60*60)) ,  (ctime / 60) , (ctime % 60)) )
	  else:
	    ctime = proc.timeend - proc.timestart
	    item.setText(4, "%.2d:%.2d:%.2d" % ( (ctime / (60*60)) ,  (ctime / 60) , (ctime % 60)) )

    def deleteInfoProcess(self):
        self.clear()

class procMB(QMessageBox):
  def __init__(self, parent, mainWindow, pid):
   QMessageBox.__init__(self, parent)
   self.setWindowTitle("Results")
   self.tm = TaskManager()
   self.pid = pid
   self.env = env.env()
   res = ""
   for proc in self.tm.lprocessus:
     if str(proc.pid) == self.pid:
	try :
          for type, name, val in self.env.get_val_map(proc.res.val_m):
	        res += name + ": " + val + "\n"
        except AttributeError:
              pass
        mainWindow.emit(SIGNAL("strResultView"), proc)
   if res == "":
      res = "No result"		
   self.setText(res)
