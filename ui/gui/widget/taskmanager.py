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

import time
from datetime import datetime
from PyQt4.QtGui import QAction, QApplication, QDockWidget, QIcon,  QHBoxLayout, QPushButton, QTabWidget, QTreeWidget, QTreeWidgetItem, QWidget, QDialog, QGridLayout, QLabel, QComboBox, QVBoxLayout, QHBoxLayout, QDialogButtonBox
from PyQt4.QtCore import QRect, QSize, Qt, SIGNAL, QEvent
from api.taskmanager.taskmanager import TaskManager
from api.gui.widget.varianttreewidget import VariantTreeWidget
from ui.gui.resources.ui_taskmanager import Ui_TaskManager

class Processus(QTreeWidget, Ui_TaskManager):
    def __init__(self, parent):
        super(QTreeWidget, self).__init__()
        self.setupUi(self)
        self.__mainWindow = parent        
        self.name = "Task manager"
        self.tm = TaskManager()
        self.initTreeProcess()
        
    def initTreeProcess(self):
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
          stime = datetime.fromtimestamp(proc.timestart)
          if proc.timeend:
	    etime = datetime.fromtimestamp(proc.timeend)
          else:
	    etime = datetime.fromtimestamp(time.time())
	  delta = etime - stime
	  item.setText(4, str(delta))

    def deleteInfoProcess(self):
        self.clear()

    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
        else:
            QTreeWidget.changeEvent(self, event)


class procMB(QDialog):
    def __init__(self, parent, mainWindow, pid):
        QDialog.__init__(self, parent)
        self.translation()
        self.setWindowTitle(self.nameTitle)
        self.tm = TaskManager()
        self.pid = pid
        res = {}
        self.tabwidget = QTabWidget(self)
        for proc in self.tm.lprocessus:
            if str(proc.pid) == self.pid:
                res = proc.res
                args = proc.args
        self.box = QVBoxLayout()
        self.setLayout(self.box)
        self.box.addWidget(self.tabwidget)
        self.dialogButtonsLayout = QHBoxLayout()
        self.dialogButtonsBox = QDialogButtonBox()
        self.dialogButtonsBox.setStandardButtons(QDialogButtonBox.Ok)
        self.connect(self.dialogButtonsBox, SIGNAL("accepted()"), self.accept)
        self.dialogButtonsLayout.addWidget(self.dialogButtonsBox)
        self.setMinimumSize(800, 600)
        if len(args) > 0:
            self.treeargs = VariantTreeWidget(self)
            self.treeargs.fillMap(self.treeargs, args)
            self.tabwidget.addTab(self.treeargs, self.argname)
            for i in [0, 1]:
                self.treeargs.resizeColumnToContents(i)
        if len(res) > 0:
            self.treeres = VariantTreeWidget(self)
            self.treeres.fillMap(self.treeres, res)
            self.tabwidget.addTab(self.treeres, self.resname)
            for i in [0, 1]:
                self.treeres.resizeColumnToContents(i)
        else:
            label = QLabel(self.noResult)
            label.setAlignment(Qt.AlignCenter)
            self.tabwidget.addTab(label, self.resname)
        self.box.addLayout(self.dialogButtonsLayout)
            

    def translation(self):
        self.argname = self.tr("Provided Arguments")
        self.resname = self.tr("Results")
        self.nameTitle = self.tr('Processus Information')
        self.noResult = self.tr("No results")
