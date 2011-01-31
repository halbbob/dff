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

from api.loader import *
from api.env import *
from api.taskmanager.taskmanager import *

from ui.gui.utils.utils import Utils

class Modules(QTreeWidget):
    def __init__(self, parent):
        QTreeWidget.__init__(self, parent)
        self.name = "Modules"
        self.env = env.env()
        self.tm = TaskManager()
        self.loader = loader.loader()
        self.initTreeModule()

    def initTreeModule(self):
        self.setColumnCount(3)
        headerLabel = [self.tr("Name"), self.tr("Key"), self.tr("Value"),
                       self.tr("Info"), self.tr("Type")]
        self.setHeaderLabels(headerLabel)
        self.setAlternatingRowColors(True)
        self.itemModuleDic = dict()
	self.itemListArgDic = dict()
	self.itemArgDic = dict()
	self.itemListResDic = dict()
	self.itemResDic = dict()

    def LoadInfoModules(self):
        modules = self.loader.modules
        for mod in modules :
	  try  :
	    itemModule = self.itemModuleDic[mod]
	  except KeyError:
	    itemModule = QTreeWidgetItem(self)
	    self.itemModuleDic[mod] = itemModule
	    itemModule.setText(0, str(mod))
	    itemConfig = QTreeWidgetItem(itemModule)
	    itemConfig.setText(0, "Config")
	    cdesc = modules[mod].conf.descr_l
	    for key in cdesc:
	       itemConfKey = QTreeWidgetItem(itemConfig) 
	       itemConfKey.setText(0, "var")	
	       itemConfKey.setText(1, key.name)
	       itemConfKey.setText(4, key.type)
	       if len(key.description):
	         itemConfKey.setText(3, key.description)
	    for type, name, val, _from in self.env.get_val_list(modules[mod].conf.val_l): 
	       itemConfKey = QTreeWidgetItem(itemConfig)
	       itemConfKey.setText(0, "const")
	       itemConfKey.setText(1, name)
	       itemConfKey.setText(2, val)
	       itemConfKey.setText(4, type)	
	  for proc in self.tm.lprocessus:
	    if proc.mod.name == mod:
	     try :
	        itemListArg = self.itemListArgDic[mod]	
	     except KeyError:
	        itemListArg = QTreeWidgetItem(itemModule)
	        self.itemListArgDic[mod] = itemListArg
	        itemListArg.setText(0, "Arg")
	     for type, name, val in self.env.get_val_map(proc.args.val_m):
               try:
	         itemArgKey = self.itemArgDic[(type, name, val)]  		
	       except KeyError:
	         itemArgKey = QTreeWidgetItem(itemListArg)    
	         self.itemArgDic[(type, name, val)] = itemArgKey	
	         itemArgKey.setText(1, name)
	         itemArgKey.setText(2, val)
	         itemArgKey.setText(4, type)
	     try :
	        itemListRes = self.itemListResDic[mod]	
	     except KeyError:
	        itemListRes = QTreeWidgetItem(itemModule)
	        self.itemListResDic[mod] = itemListRes
	        itemListRes.setText(0, "Results")
             result = proc.res
             if result:
                 val_map = self.env.get_val_map(result.val_m)
                 for type, name, val in val_map:
                     try:
                         itemResKey = self.itemResDic[(type, name, val)]  		
                     except KeyError:
                         itemResKey = QTreeWidgetItem(itemListRes)    
                         self.itemResDic[(type, name, val)] = itemResKey	
                         itemResKey.setText(1, name)
                         itemResKey.setText(2, val)
                         itemResKey.setText(4, type)
	          		    	 	    		
    def deleteInfoModule(self):
	self.clear()
