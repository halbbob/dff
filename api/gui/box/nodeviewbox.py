# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2010 ArxSys
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

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *

#from api.gui.widget.nodefilterbox import NodeFilterBox
from api.gui.widget.propertytable import PropertyTable

class NodeViewBox(QGroupBox):
  def __init__(self, parent):
    QGroupBox.__init__(self, "View")
    self.parent = parent
    self.button = {}
    self.gridLayout = QHBoxLayout(self)
    self.gridLayout.setAlignment(Qt.AlignLeft)
    self.addPropertyTable()
    self.createButton("top", self.moveToTop, ":previous.png")
    self.createButton("table", self.tableActivated,  ":view_detailed.png")
    self.createButton("thumb", self.thumbActivated, ":view_icon.png")
    self.createButton("leftTree", self.leftTreeActivated, ":view_choose.png")
    self.createButton("imagethumb", self.imagethumbActivated, ":image.png")
    self.createButton("search", self.searchActivated, ":filefind.png")
    self.createThumbSize()
    self.createCheckBoxAttribute()
    self.tableActivated()
    self.setLayout(self.gridLayout)

  def addPropertyTable(self):
    self.propertyTable = PropertyTable(self)
    self.propertyTable.setVisible(False)
    self.propertyTable.setMinimumSize(QSize(150, 300))
    self.parent.browserLayout.addWidget(self.propertyTable)

  def createButton(self, name, func, iconName, iconSize = 32):
    self.button[name] = QPushButton(self)
    self.button[name].setFixedSize(QSize(iconSize, iconSize))
    self.button[name].setFlat(True)
    self.button[name].setIcon(QIcon(iconName))
    self.button[name].setIconSize(QSize(iconSize, iconSize))
    self.gridLayout.addWidget(self.button[name])
    self.parent.connect(self.button[name], SIGNAL("clicked()"), func)

  def createThumbSize(self):
    self.thumbSize = QComboBox()
    self.thumbSize.setMaximumWidth(100)
    self.thumbSize.addItem("Small")
    self.thumbSize.addItem("Medium")
    self.thumbSize.addItem("Large")
    self.thumbSize.setEnabled(False)
    label = QLabel("Icon size:") 
    self.parent.connect(self.thumbSize, SIGNAL("currentIndexChanged(QString)"), self.parent.sizeChanged)
    self.gridLayout.addWidget(label)
    self.gridLayout.addWidget(self.thumbSize)
    self.button["thumb"].setEnabled(True)

  def createCheckBoxAttribute(self):
    self.checkboxAttribute = QCheckBox("Show attributes", self)
    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.checkboxAttribute.setCheckState(False)
    self.checkboxAttribute.setEnabled(False)
    self.checkboxAttribute.setTristate(False)

    self.connect(self.checkboxAttribute, SIGNAL("stateChanged(int)"), self.checkboxAttributeChanged) 
    self.gridLayout.addWidget(self.checkboxAttribute)
    self.button["table"].setEnabled(False)

  def checkboxAttributeChanged(self, state):
     if state:
       if self.parent.thumbsView.isVisible():
         self.propertyTable.setVisible(True)
     else:
        self.propertyTable.setVisible(False)	

  def moveToTop(self):
     parent =  self.parent.model.rootItem.parent()
     self.parent.model.setRootPath(parent)
 
  def imagethumbActivated(self):
     if self.parent.model.imagesThumbnails():
       self.parent.model.setImagesThumbnails(False)
       self.parent.model.reset()
     else:
      self.parent.model.setImagesThumbnails(True)
      self.parent.model.reset()
     pass
 
  def leftTreeActivated(self):
     if self.parent.treeView.isVisible():
       self.parent.treeView.setVisible(False)
     else:
       self.parent.treeView.setVisible(True)
 
  def tableActivated(self):
     self.parent.tableView.setVisible(True)
     self.parent.thumbsView.setVisible(False)
     self.checkboxAttribute.setEnabled(False)
     self.propertyTable.setVisible(False)
     self.button["thumb"].setEnabled(True)
     self.thumbSize.setEnabled(False)
     self.button["table"].setEnabled(False)
  
  def thumbActivated(self):
     self.checkboxAttribute.setEnabled(True)
     if self.checkboxAttribute.isChecked():
       self.propertyTable.setVisible(True)
     else :
        self.propertyTable.setVisible(False)
     self.parent.tableView.setVisible(False)
     self.parent.thumbsView.setVisible(True)
     self.button["thumb"].setEnabled(False)
     self.thumbSize.setEnabled(True)
     self.button["table"].setEnabled(True)

  def searchActivated(self):
     if self.parent.nodeFilterBox.isVisible():
       self.parent.nodeFilterBox.setVisible(False) 
     else:
       self.parent.nodeFilterBox.setVisible(True) 

  def createComboBoxPath(self):
    #self.comboBoxPath = NodeComboBox(self)
    #self.comboBoxPath.setMinimumSize(QSize(251,32))
    #self.comboBoxPath.setMaximumSize(QSize(16777215,32))
    #self.buttonLayout.addWidget(self.comboBoxPath)
    #self.initCallback()
    pass 
