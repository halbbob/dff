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
# 

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *

from api.vfs import *
from api.vfs.libvfs import VFS
from api.events.libevents import EventHandler
from api.loader import loader
from api.taskmanager.taskmanager import TaskManager 
from api.types import libtypes
from api.types.libtypes import typeId, Variant

from api.gui.box.nodefilterbox import NodeFilterBox
from api.gui.box.nodeviewbox import NodeViewBox
from api.gui.dialog.applymodule import ApplyModule
from api.gui.dialog.extractor import Extractor
from api.gui.widget.nodeview import NodeThumbsView, NodeTableView, NodeTreeView, NodeLinkTreeView 
from api.gui.widget.propertytable import PropertyTable
from api.gui.model.vfsitemmodel import  VFSItemModel, TreeModel

from ui.gui.utils.menu import MenuTags
from ui.gui.resources.ui_nodebrowser import Ui_NodeBrowser

modulePriority = {} 

class SimpleNodeBrowser(QWidget):
  def __init__(self, parent, view = NodeThumbsView):
    QWidget.__init__(self, parent)
    self.type = "filebrowser"
    self.icon = None
    self.name = "nodebrowser"
    self.setObjectName(self.name)
    self.vfs = vfs.vfs()

    self.model = VFSItemModel(self, True)
    self.model.setRootPath(self.vfs.getnode('/'))
    self.model.setThumbnails(True)

    self.view = view(self)
    self.view.setModel(self.model)

    self.box = QGridLayout()
    self.box.addWidget(self.view, 0,0)
    self.setLayout(self.box)

  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.model.translation()
    else:
      QWidget.changeEvent(self, event)


class NodeBrowser(QWidget, EventHandler, Ui_NodeBrowser):
  def __init__(self, parent):
    super(QWidget, self).__init__()
    EventHandler.__init__(self)
    self.setupUi(self)

    self.mainwindow = parent

    self.getWindowGeometry()

    self.name = self.windowTitle()
    self.type = "filebrowser"
    self.setObjectName(self.name)

    self.vfs = vfs.vfs()
    self.VFS = VFS.Get()
    self.VFS.connection(self)
    self.loader = loader.loader()
    self.lmodules = self.loader.modules
    self.taskmanager = TaskManager()

    self.parent = parent
    self.icon = None

    self.createSubMenu()
    self.createLayout()
    self.addModel("/")

    self.addNodeLinkTreeView()
    self.addNodeView()

    self.addOptionsView()

  def Event(self, e):
    self.model.emit(SIGNAL("layoutAboutToBeChanged()")) 
    self.model.emit(SIGNAL("layoutChanged()"))
    self.treeModel.emit(SIGNAL("layoutAboutToBeChanged()")) 
    self.treeModel.emit(SIGNAL("layoutChanged()"))

  def getWindowGeometry(self):
    self.winWidth = self.mainwindow.width()

  def createLayout(self):
    self.baseLayout = QVBoxLayout(self)
    self.baseLayout.setMargin(0)
    self.baseLayout.setSpacing(0)
    self.browserLayout = QSplitter(self)
    self.baseLayout.insertWidget(0, self.browserLayout)
    self.baseLayout.setStretchFactor(self.browserLayout, 1)
 
  def addOptionsView(self):
    self.nodeViewBox = NodeViewBox(self)
    self.nodeFilterBox = NodeFilterBox(self)
    self.baseLayout.insertWidget(0,self.nodeFilterBox)
    self.baseLayout.insertWidget(0, self.nodeViewBox)

  def addModel(self, path):
    self.model = VFSItemModel(self, True, True)
    self.model.setRootPath(self.vfs.getnode(path))

  ###### View searhing #####
  def addSearchView(self):
    self.search_model = VfsSearchItemModel(self, True)
    self.treeModel.setRootPath(self.vfs.getnode("/"))

  def addNodeLinkTreeView(self):
    self.treeModel = TreeModel(self, True)
    self.treeModel.setRootPath(self.vfs.getnode("/"))
    self.treeProxyModel = self.treeModel
    self.treeView = NodeLinkTreeView(self)
    self.treeView.setModel(self.treeProxyModel)

    self.browserLayout.addWidget(self.treeView)

    self.browserLayout.setStretchFactor(self.browserLayout.indexOf(self.treeView), 0)

    self.connect(self.treeView, SIGNAL("nodeTreeClicked"), self.nodeTreeDoubleClicked)
    self.connect(self.treeView, SIGNAL("nodeTreeClicked"), self.treeModel.nodeClicked)

  def addNodeView(self):
    self.addTableView()
    self.addThumbsView()

  def addTableView(self): 
    self.tableView = NodeTableView(self)

    self.tableView.horizontalHeader().setStretchLastSection(True)
    self.tableView.setModel(self.model)
    self.tableView.setColumnWidth(0, 200)
    self.tableView.setSortingEnabled(True)
    self.tableView.setSizePolicy(QSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum))
    self.browserLayout.addWidget(self.tableView)

    self.browserLayout.setStretchFactor(self.browserLayout.indexOf(self.tableView), 1)

    self.connect(self.tableView, SIGNAL("nodePressed"), self.nodePressed)
    self.connect(self.tableView, SIGNAL("nodeClicked"), self.nodeClicked)
    self.connect(self.tableView, SIGNAL("nodeDoubleClicked"), self.nodeDoubleClicked)
    self.connect(self.tableView, SIGNAL(""), self.selectAttr)

  def selectAttr(self):
    pass
    
  def addThumbsView(self):
    self.thumbsView = NodeThumbsView(self)
    self.thumbsView.setModel(self.model) 
    self.thumbsView.setSizePolicy(QSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum))
    self.browserLayout.addWidget(self.thumbsView)
    self.browserLayout.setStretchFactor(self.browserLayout.indexOf(self.thumbsView), 1)
    self.connect(self.thumbsView, SIGNAL("nodePressed"), self.nodePressed)
    self.connect(self.thumbsView, SIGNAL("nodeClicked"), self.nodeClicked)
    self.connect(self.thumbsView, SIGNAL("nodeDoubleClicked"), self.nodeDoubleClicked)

  def currentProxyModel(self):
     if self.thumbsView.isVisible():
       return self.thumbsView.model()
     elif self.tableView.isVisible():
       return self.tableView.model()

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

  def currentNodes(self):
     indexList = self.currentView().selectionModel().selectedRows()
     nodeList = []
     for index in indexList:
       if index.isValid():
         nodeList.append(self.VFS.getNodeFromPointer(index.internalId()))
     return nodeList

  def currentNode(self):
     index = self.currentView().selectionModel().currentIndex()
     if index.isValid():
         return self.VFS.getNodeFromPointer(index.internalId())

  def nodePressed(self, key, node, index = None):
    if key in [Qt.Key_Up, Qt.Key_Down, Qt.Key_PageUp, Qt.Key_PageDown]:
      if self.nodeViewBox.propertyTable.isVisible():
        self.nodeViewBox.propertyTable.fill(node)
    if key == Qt.Key_Return:
      if self.currentView().enterInDirectory:
        if node.hasChildren() or node.isDir():
          self.currentModel().setRootPath(node)
        else:
          self.openDefault(node)
      else:
        self.openDefault(node)
    if key == Qt.Key_Backspace:
      self.currentModel().setRootPath(node.parent().parent())

  def nodeClicked(self, mouseButton, node, index = None):
     if mouseButton == Qt.LeftButton:
         if self.nodeViewBox.propertyTable.isVisible():
            self.nodeViewBox.propertyTable.fill(node)
     if mouseButton == Qt.RightButton:
       if node.hasChildren() or node.isDir():
         self.actionOpen_in_new_tab.setEnabled(True)
       else:
         self.actionOpen_in_new_tab.setEnabled(False)
       self.submenuFile.popup(QCursor.pos())
       self.submenuFile.show()       

  def nodeTreeDoubleClicked(self, mouseButton, node, index = None):
    if node == None:
      return
    if self.currentView().enterInDirectory:
      if node.hasChildren() or node.isDir():
        self.currentModel().setRootPath(node) 

  def nodeDoubleClicked(self, mouseButton, node, index = None):
    if node == None:
      return
    if self.currentView().enterInDirectory:
      if node.hasChildren() or node.isDir():
        self.currentModel().setRootPath(node) 
      else:
        self.openDefault(node)
    else:  
      self.openDefault(node)

  def sizeChanged(self, string):
     if self.nodeViewBox.thumbSize.currentIndex() == 0:
       self.thumbsView.setIconGridSize(64, 64)
     elif self.nodeViewBox.thumbSize.currentIndex() == 1:
       self.thumbsView.setIconGridSize(96, 96)
     elif self.nodeViewBox.thumbSize.currentIndex() == 2:
       self.thumbsView.setIconGridSize(128, 128)

  def openDefault(self, node = None):
     if not node:
       node = self.currentNode()
       if not node:
	 return
     mods = node.compatibleModules()
     if len(mods):
       for mod in mods:
          if "Viewers" in self.lmodules[mod].tags:
	    break
       try:
         priority = modulePriority[mod] #XXX put in conf
       except KeyError:
         modulePriority[mod] = 0
         priority = 0
       if not priority: 
        #XXX translate
         mbox = QMessageBox(QMessageBox.Question, self.tr("Apply module"), self.tr("Do you want to apply module ") + str(mod) + self.tr(" on this node ?"), QMessageBox.Yes | QMessageBox.No, self)
         mbox.addButton(self.tr("Always"), QMessageBox.AcceptRole)
	 reply = mbox.exec_() 
         if reply == QMessageBox.No:
           return		
         elif reply == QMessageBox.AcceptRole:
	   modulePriority[mod] = 1 
       if self.lmodules[mod]:
         conf = self.lmodules[mod].conf
         arguments = conf.arguments()
         marg = {}
         for argument in arguments:
           if argument.type() == typeId.Node:
             marg[argument.name()] = node
         args = conf.generate(marg)
         self.taskmanager.add(mod, args, ["thread", "gui"])       
	 return
     else:
       conf = self.lmodules["hexadecimal"].conf
       args = conf.generate({"file": node})
       self.taskmanager.add("hexadecimal", args, ["thread", "gui"])
 
  def createSubMenu(self):
     self.extractor = Extractor(self.parent)
     self.connect(self.extractor, SIGNAL("filled"), self.launchExtract)
     self.submenuFile = QMenu()
     self.submenuFile.addAction(self.actionOpen)
     self.connect(self.actionOpen, SIGNAL("triggered()"), self.openDefault)
     self.submenuFile.addAction(self.actionOpen_in_new_tab)
     self.connect(self.actionOpen_in_new_tab, SIGNAL("triggered()"), self.openAsNewTab)
     self.menu = {}
     self.menuModule = self.submenuFile.addMenu(self.actionOpen_with.icon(), self.actionOpen_with.text())
     self.menuTags = MenuTags(self, self.parent, self.currentNodes)
     self.submenuFile.addSeparator()
     self.submenuFile.addAction(self.actionHex_viewer)
     self.connect(self.actionHex_viewer, SIGNAL("triggered()"), self.launchHexedit)
     self.submenuFile.addAction(self.actionExtract)
     self.connect(self.actionExtract, SIGNAL("triggered()"), self.extractNodes)
     self.submenuFile.addSeparator()

  def openAsNewTab(self):
    node = self.currentNode()
    self.mainwindow.addNodeBrowser(node)

  def launchHexedit(self):
     nodes = self.currentNodes()
     for node in nodes:
       conf = self.loader.get_conf("hexadecimal")
       try:
         arg = conf.generate({"file": node})
         self.taskmanager.add("hexadecimal", arg, ["thread", "gui"])
       except RuntimeError:
         pass

  def extractNodes(self):
     self.extractor.launch(self.currentNodes())

  def launchExtract(self):
     res = self.extractor.getArgs()
     arg = libtypes.Arguments("gui_input")
     lnodes.thisown = 0
     for node in res["nodes"]:
        lnodes.append(node)
     arg.thisown = 0
     arg.add_path("syspath", str(res["path"]))
     arg.add_lnode("files", lnodes)
     arg.add_bool("recursive", int(res["recurse"]))
     self.taskmanager.add("extract", arg, ["thread", "gui"])

  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.retranslateUi(self)
      self.menuModule.setTitle(self.actionOpen_with.text())
      self.model.translation()
      self.treeModel.translation()
    else:
      QWidget.changeEvent(self, event)


