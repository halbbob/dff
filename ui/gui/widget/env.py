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

from api.env import *

from ui.gui.utils.utils import Utils

class Env(QTreeWidget):
    def __init__(self, parent):
        QTreeWidget.__init__(self, parent)
        self.name = "Environment"
        self.env = env.env()
        self.initTreeEnv()

    def initTreeEnv(self):
        self.setColumnCount(3)
        headerLabel = [self.tr("Key"), 
        self.tr("Type"), 
        self.tr("Value"), 
        self.tr("From")]
        self.setHeaderLabels(headerLabel)
        self.setAlternatingRowColors(True)
	self.envItemDic = dict()
	self.envConfKeyDic = dict()
	self.envValKeyDic = dict()
 
    def LoadInfoEnv(self):
        db = self.env.vars_db
        for key in db : 
          try :
	    (itemEnv, itemVar, itemValues) = self.envItemDic[key]
	  except KeyError:
	    itemEnv = QTreeWidgetItem(self)
	    itemEnv.setText(0, key)
	    itemVar = QTreeWidgetItem(itemEnv)
            itemVar.setText(0, "var")
	    itemValues = QTreeWidgetItem(itemEnv)
	    self.envItemDic[key] = (itemEnv, itemVar, itemValues)
	  cdesc = db[key].descr_l
	  for vk in cdesc:
	    try:
	      itemConfKey = self.envConfKeyDic[(vk.type, vk._from)]	     
	    except KeyError:
	      itemConfKey = QTreeWidgetItem(itemVar) 
	      self.envConfKeyDic[(vk.type, vk._from)] = itemConfKey
	      itemConfKey.setText(1, vk.type)
	      itemConfKey.setText(3, vk._from)
          itemValues.setText(0, "values")
	  for type, name, val, _from in self.env.get_val_list(db[key].val_l): 
	   try:
	      itemValKey = self.envValKeyDic[(type, _from, val)]
	   except:
	      itemValKey = QTreeWidgetItem(itemValues)
              self.envValKeyDic[(type, _from, val)] = itemValKey
	      itemValKey.setText(1, type)
	      itemValKey.setText(2, val)
	      itemValKey.setText(3, _from)

    def deleteInfoEnv(self):
        self.clear()
