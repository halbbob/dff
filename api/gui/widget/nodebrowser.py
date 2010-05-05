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
from api.gui.dialog.extractor import Extractor
from ui.gui.utils.menu import MenuTags

#try non threader ?
from api.magic.filetype import *
from api.loader import *
from api.taskmanager.taskmanager import *
from api.env import *

import sip

class NodeViewEvent():
  def __init__(self, parent = None):
   self.enterInDirectory = None 
   self.parent = parent

  def mouseReleaseEvent(self, e):
     index = self.indexAt(e.pos())
     if index.isValid():
       node = index.internalPointer()
       self.emit(SIGNAL("nodeClicked"), e.button(), node)

  def mouseDoubleClickEvent(self, e):
     index = self.indexAt(e.pos())
     if index.isValid():
       node = index.internalPointer()
       self.emit(SIGNAL("nodeDoubleClicked"), e.button(), node) 

  def setEnterInDirectory(self, flag):
     self.enterInDirectory = flag  
 
class NodeThumbsView(QListView, NodeViewEvent):
  def __init__(self, parent):
     QListView.__init__(self, parent)
     NodeViewEvent.__init__(self, parent)
     width = 64
     height = 64
     self.setIconSize(width,  height)       
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
 
  def setIconSize(self, width, height):
    QListView.setIconSize(self, QSize(width, height))
    self.setGridSize(QSize(width + 10, height + 20)) 

class NodeTreeView(QTreeView, NodeViewEvent):
  def __init__(self, parent):
     QTreeView.__init__(self, parent)
     NodeViewEvent.__init__(self, parent) 

class NodeTableView(QTableView, NodeViewEvent):
   def __init__(self, parent):
      QTableView.__init__(self, parent)
      NodeViewEvent.__init__(self, parent)
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

class VFSItemProxyModel(QSortFilterProxyModel, VFSItemModel):
  def __init__(self, parent):
    VFSItemModel.__init__(self, parent)
    QSortFilterProxyModel.__init__(self, parent)
    self.parent = parent

  #def mapFromSource(self, index):
     #print "map from source"
     
     #return QModelIndex()

  #def mapSelectionFromSource(self, itemSelection):
     #print "map selection from source"
     #return QItemSelection()

  #def mapSelectionToSource(self, itemSelection):
     #print "map selection to source"
     #return QItemSelection()

  #def mapToSource(self, index):
     #print "map to source"
     #if index.isValid():
       #print index.internalPointer()
     #return QModelIndex()

  #def setSourceModel(self, model):
     #self.model = model

  #def sourceModel(self):
     #return self.model

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
    self.ft = FILETYPE()
    self.env = env.env()	
    self.loader = loader.loader()
    self.lmodules = self.loader.modules
    self.taskmanager = TaskManager()

    self.setMinimumSize(QSize(400, 300))
#gestion du click droit 
    self.createSubMenu()
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

    #re threader ? + regeneration des icones a chaque fois ! remettre le cache + autre system ?
    #self.model.setThumbnails(True)

    self.tableView = NodeTableView(self)
    #self.tableView.setModel(self.model)
    self.tableProxyModel = QSortFilterProxyModel(self)
    self.tableProxyModel.setSourceModel(self.model)

    self.model.setDirPath(self.vfs.getnode('/'))
    self.tableView.setModel(self.tableProxyModel)
    self.tableView.setSortingEnabled(True)
    #self.tableView.setSortingEnabled(True)
#XXX rajouter un bouton sort case sensitive
#self.tableView.sortCaseSensitive() 
    self.vlayout.addWidget(self.tableView)

    #self.treeView = NodeTreeView(self)
    #self.treeView.setModel(self.model)
    #self.vlayout.addWidget(self.treeView)

    self.thumbsView = NodeThumbsView(self)
    #self.thumbsProxyModel = VFSItemProxyModel(self)
    #self.thumbsProxyModel.setSourceModel(self.model)
    #self.thumbsView.setModel(self.thumbsProxyModel)    
#    self.thumbsView.setSortingEnabled(True)
    
    self.thumbsView.setModel(self.model)
    self.vlayout.addWidget(self.thumbsView)

    self.connect(self.tableView, SIGNAL("nodeClicked"), self.nodeClicked)
    self.connect(self.thumbsView, SIGNAL("nodeClicked"), self.nodeClicked)
    self.connect(self.tableView, SIGNAL("nodeDoubleClicked"), self.nodeDoubleClicked)
    self.connect(self.thumbsView, SIGNAL("nodeDoubleClicked"), self.nodeDoubleClicked)


    self.createButton("top", self.moveToTop, ":previous.png")
    self.createButton("table", self.tableActivated,  ":list.png")
    self.createButton("thumb", self.thumbActivated, ":image.png")

    self.thumSize = QComboBox()
    self.thumSize.setMaximumWidth(100)
    self.thumSize.addItem("Small")
    self.thumSize.addItem("Medium")
    self.thumSize.addItem("Large")
    self.connect(self.thumSize, SIGNAL("currentIndexChanged(QString)"), self.sizeChanged)
    self.hlayout.addWidget(self.thumSize)

    self.checkboxAttribute = QCheckBox("Show Attributes")
    self.checkboxAttribute.setCheckState(False)
    self.checkboxAttribute.setEnabled(False)
    self.connect(self.checkboxAttribute, SIGNAL("stateChanged(int)"), self.checkboxAttributeChanged) 
    self.hlayout.addWidget(self.checkboxAttribute)

    self.checkboxAttribute.setEnabled(False)
    self.button["thumb"].setEnabled(True)
    self.thumSize.setEnabled(False)
    #self.treeButton.setEnabled(False)
    self.button["table"].setEnabled(False)
       

#mettre ds un autre layout avec une text box Filter:
    self.filterEdit = QLineEdit(self)
    self.hlayout.addWidget(self.filterEdit)
    self.connect(self.filterEdit, SIGNAL("textChanged(QString)"), self.tableProxyModel.setFilterWildcard)


    #self.comboBoxPath = NodeComboBox(self)
    #self.comboBoxPath.setMinimumSize(QSize(251,32))
    #self.comboBoxPath.setMaximumSize(QSize(16777215,32))
    #self.hlayout.addWidget(self.comboBoxPath)
 
    #self.initCallback()
    self.tableActivated()

  def currentModel(self):
     if self.thumbsView.isVisible():
       return self.thumbsView.model()
     elif self.tableView.isVisible():
       return self.tableView.model()
 
  def currentView(self):
     if self.thumbsView.isVisible():
       return self.thumbsView
     elif self.tableView.isVisible():
       return self.tableView
  #currentSelectedNodes
  def currentNodes(self):
     indexList = self.currentView().selectedIndexes()
     nodeList = []
     for index in indexList:
       if index.isValid():
         nodeList.append(index.internalPointer())
     return nodeList

  def currentNode(self):
     index = self.currentView().currentIndex()
     if index.isValid():
         return index.internalPointer()

  def nodeClicked(self, mouseButton, node):
     if mouseButton == Qt.LeftButton:
         if self.propertyTable.isVisible():
            self.propertyTable.fill(node)
     if mouseButton == Qt.RightButton:
       self.submenuFile.popup(QCursor.pos())
       self.submenuFile.show()       

  def nodeDoubleClicked(self, mouseButton, node):
     if self.currentView().enterInDirectory:
       if len(node.next):
#XXX
	 self.currentModel().setDirPath(node) 
       else:	
	 self.openDefault(node)
     else:  
         self.openDefault(node)


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
     self.checkboxAttribute.setEnabled(False)
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

  def checkboxAttributeChanged(self, state):
     if state:
       if self.thumbsView.isVisible():
         self.propertyTable.setVisible(True)
     else:
        self.propertyTable.setVisible(False)	

  def openDefault(self, node = None):
     if not node:
       print "open default without node"
       node = self.currentNode()
       if not node:
	 return
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

 
  def createSubMenu(self):
     self.extractor = Extractor(self.parent)
     self.connect(self.extractor, SIGNAL("filled"), self.launchExtract)
     self.submenuFile = QMenu()
     self.submenuFile.addAction(QIcon(":exec.png"),  "Open", self.openDefault, "Open")
     self.menu = {}
     self.menu["Modules"] = self.submenuFile.addMenu(QIcon(":exec.png"),  "Open With")
     self.menuTags = MenuTags(self, self.parent, self.currentNodes)
     self.submenuFile.addSeparator()
     self.submenuFile.addAction(QIcon(":hexedit.png"), "Hexeditor", self.launchHexedit, "Hexedit")
     self.submenuFile.addAction(QIcon(":extract.png"),  "Extract", self.extractNodes, "ExtractNode")
     self.submenuFile.addSeparator()
								#self -> signal receivver #signal
     self.submenuFile.addAction(QIcon(":info.png"),  "Property", self.launchProperty, "Property")

  def launchHexedit(self):
     nodes = self.currentNodes()
     for node in nodes:
        arg = self.env.libenv.argument("gui_input")
        arg.thisown = 0
        arg.add_node("file", node)
        self.taskmanager.add("hexedit", arg, ["thread", "gui"])

  def launchProperty(self):
     #if not self.parent.PropertyDialog.isVisible():
       #self.parent.PropertyDialog.fillInfo(self.currentNodeDir, self.getListCurrentNode())
       #iReturn = self.parent.PropertyDialog.exec_()
       #self.parent.PropertyDialog.removeAttr()
     #else:
       #QMessageBox.critical(self, "Erreur", u"This box is already open")
     pass
 
  def extractNodes(self):
     self.extractor.launch(self.currentNodes())


  def launchExtract(self):
     res = self.extractor.getArgs()
     arg = self.env.libenv.argument("gui_input")
     lnodes = self.env.libenv.ListNode()
     lnodes.thisown = 0
     for node in res["nodes"]:
        lnodes.append(node)
     arg.thisown = 0
     arg.add_path("syspath", str(res["path"]))
     arg.add_lnode("files", lnodes)
     arg.add_bool("recursive", int(res["recurse"]))
     self.taskmanager.add("extract", arg, ["thread", "gui"])

  def sizeChanged(self, string):
     if string == "Small":
       self.thumbsView.setIconSize(64, 64)
     elif string == "Medium":
       self.thumbsView.setIconSize(96, 96)
     elif string == "Large":
       self.thumbsView.setIconSize(128, 128)


