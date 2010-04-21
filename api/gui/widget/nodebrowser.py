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

from api.vfs import *


from api.gui.widget.propertytable import PropertyTable
from api.gui.model.vfsitemmodel import  VFSItemModel
#try non threader ?
from api.magic.filetype import *
from api.loader import *
from api.taskmanager.taskmanager import *
from api.env import *

class NodeViewEvent():
  def __init__(self):
    self.ft = FILETYPE()
    self.env = env.env()	
    self.loader = loader.loader()
    self.lmodules = self.loader.modules
    self.taskmanager = TaskManager()
    self.enterInDirectory = None 

  def mouseDoubleClickEvent(self, e):
    index = self.indexAt(e.pos())
    if index.isValid():
      node = index.internalPointer() 
      if self.enterInDirectory:
        if len(node.next):
	  self.model().setDirPath(node) 
	else:	
	  self.openDefault(node)
      else:  
        self.openDefault(node)

  def setEnterInDirectory(self, flag):
     self.enterInDirectory = flag  

  def openDefault(self, node):
      arg = self.env.libenv.argument("gui_input")
      arg.thisown = 0 
      try:
        mod = self.ft.findcompattype(node)[0]
        if self.lmodules[mod]:
          conf = self.lmodules[mod].conf
          cdl = conf.descr_l
          for a in cdl:
            if a.type == "node":
              arg.add_node(a.name, node)
        self.taskmanager.add(mod, arg, ["thread", "gui"])       
      except IndexError: 
        arg.add_node("file", node)
        self.taskmanager.add("hexedit", arg, ["thread", "gui"])        
 
class NodeThumbsView(QListView, NodeViewEvent):
  def __init__(self, parent):
     QListView.__init__(self, parent)
     NodeViewEvent.__init__(self)
     width = 64
     height = 64
     self.setIconSize(QSize(width,  height))       
     self.setGridSize(QSize(width + 10, height + 20)) 
     self.setFlow(QListView.LeftToRight)
     self.setLayoutMode(QListView.SinglePass)
     self.setSelectionMode(QAbstractItemView.ExtendedSelection)
     self.setSelectionBehavior(QAbstractItemView.SelectRows)
     self.setViewMode(QListView.IconMode)
     self.setUniformItemSizes(False)
     self.setMovement(QListView.Static)
     self.setSelectionRectVisible(True)
     self.setResizeMode(QListView.Adjust)
     self.setEnterInDirectory(True)

class NodeTreeView(QTreeView, NodeViewEvent):
  def __init__(self, parent):
     QTreeView.__init__(self, parent)
     NodeViewEvent.__init__(self) 

class NodeTableView(QTableView, NodeViewEvent):
   def __init__(self, parent):
      QTableView.__init__(self, parent)
      NodeViewEvent.__init__(self)
      self.setShowGrid(False)
      self.setEnterInDirectory(True)
#changer les font et pas afficher colone de gauche?

class SimpleNodeBrowser(QWidget):
  def __init__(self, parent, view = NodeThumbsView):
    QWidget.__init__(self, parent)
    self.type = "filebrowser"
    self.icon = None
    self.name = "nodebrowser"
    self.setObjectName(self.name)
    self.vfs = vfs.vfs()

    self.model = VFSItemModel(self)
    self.model.setDirPath(self.vfs.getnode('/'))
    self.model.setThumbnails(True)

    self.view = view(self)
    self.view.setModel(self.model)

    self.box = QGridLayout()
    self.box.addWidget(self.view, 0,0)
    self.setLayout(self.box)

class NodeBrowser(QWidget):
  def __init__(self, parent):
    QWidget.__init__(self, parent)
    self.type = "filebrowser"
    self.icon = None
    self.name = "nodebrowser"
    self.setObjectName(self.name)
    self.vfs = vfs.vfs()
    self.parent = parent
    self.button = {}
#
    self.setMinimumSize(QSize(400, 300))
    #self.createSubMenu()
    self.hbaselayout = QHBoxLayout(self)
    self.vlayout = QVBoxLayout()
    self.hlayout = QHBoxLayout()
    self.vlayout.addLayout(self.hlayout)

    self.propertyTable = PropertyTable(self)
    self.propertyTable.setVisible(False)
    self.propertyTable.setMinimumSize(QSize(150, 300))
    self.hbaselayout.addWidget(self.propertyTable)

    self.hbaselayout.addLayout(self.vlayout)
    self.model = VFSItemModel(self)
    self.model.setDirPath(self.vfs.getnode('/'))
    #self.model.setThumbnails(True)

    self.tableView = NodeTableView(self)
    self.tableView.setModel(self.model)
    self.vlayout.addWidget(self.tableView)

    #self.treeView = NodeTreeView(self)
    #self.treeView.setModel(self.model)
    #self.vlayout.addWidget(self.treeView)

    self.thumbsView = NodeThumbsView(self)
    self.thumbsView.setModel(self.model)
    self.vlayout.addWidget(self.thumbsView)

    self.createButton("top", self.moveToTop, ":previous.png")
    self.createButton("table", self.tableActivated,  ":list.png")
    self.createButton("thumb", self.thumbActivated, ":image.png")

    self.thumSize = QComboBox()
    self.thumSize.setMaximumWidth(100)
    self.thumSize.addItem("Small")
    self.thumSize.addItem("Medium")
    self.thumSize.addItem("Large")
    #self.connect(self.thumSize, SIGNAL("currentIndexChanged(QString)"), self.sizeChanged)
    self.hlayout.addWidget(self.thumSize)

    self.checkboxAttribute = QCheckBox("Show Attributes")
    self.checkboxAttribute.setCheckState(False)
    #self.connect(self.checkboxAttribute, SIGNAL("stateChanged(int)"), self.checkboxAttributeChanged) 
    self.hlayout.addWidget(self.checkboxAttribute)

    self.checkboxAttribute.setEnabled(False)
    self.button["thumb"].setEnabled(True)
    self.thumSize.setEnabled(False)
    #self.treeButton.setEnabled(False)
    self.button["table"].setEnabled(False)
        
    #self.comboBoxPath = NodeComboBox(self)
    #self.comboBoxPath.setMinimumSize(QSize(251,32))
    #self.comboBoxPath.setMaximumSize(QSize(16777215,32))
    #self.hlayout.addWidget(self.comboBoxPath)
 
    #self.initCallback()
    self.tableActivated()

  def createButton(self, name, func, iconName, iconSize = 32):
     self.button[name] = QPushButton(self)
     self.button[name].setFixedSize(QSize(iconSize, iconSize))
     self.button[name].setFlat(True)
     self.button[name].setIcon(QIcon(iconName))
     self.button[name].setIconSize(QSize(iconSize, iconSize))
     self.hlayout.addWidget(self.button[name])
     self.connect(self.button[name], SIGNAL("clicked()"), func)
 
  #def initCallback(self):
     #self.connect(self.comboBoxPath, SIGNAL("currentIndexChanged(const QString & )"),  self.comboBoxPathChanged)
       
  def moveToTop(self):
     parent =  self.model.rootItem.parent
     self.model.setDirPath(parent)
     
  def tableActivated(self):
     self.tableView.setVisible(True)
     self.thumbsView.setVisible(False)
#    self.treeView.setVisible(False)
     #self.reloadChangedView()
##
     self.propertyTable.setVisible(False)
     self.button["thumb"].setEnabled(True)
     self.thumSize.setEnabled(False)
     self.button["table"].setEnabled(False)
     #self.topButton.setEnabled(False)
  
  def thumbActivated(self):
#XXX if button checked
     self.checkboxAttribute.setEnabled(True)
     if self.checkboxAttribute.isChecked():
       self.propertyTable.setVisible(True)
     else :
        self.propertyTable.setVisible(False)
     #self.treeView.setVisible(False)
     self.tableView.setVisible(False)
     self.thumbsView.setVisible(True)
#     self.reloadChangedView()
#
     self.button["thumb"].setEnabled(False)
     self.thumSize.setEnabled(True)
     #self.treeButton.setEnabled(True)
     self.button["table"].setEnabled(True)
     #self.topButton.setEnabled(True)

