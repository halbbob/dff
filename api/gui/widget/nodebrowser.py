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
from api.vfs.libvfs import VFS, DEventHandler
from api.magic.filetype import *
from api.loader import *
from api.taskmanager.taskmanager import *
from api.env import *

from api.gui.box.nodefilterbox import NodeFilterBox
from api.gui.box.nodeviewbox import NodeViewBox
from api.gui.dialog.property import Property
from api.gui.dialog.applymodule import ApplyModule
from api.gui.dialog.extractor import Extractor
from api.gui.widget.nodeview import NodeThumbsView, NodeTableView, NodeTreeView, NodeLinkTreeView 
from api.gui.widget.propertytable import PropertyTable
from api.gui.model.vfsitemmodel import  VFSItemModel

from ui.gui.utils.menu import MenuTags

class NodeTreeProxyModel(QSortFilterProxyModel):
  def __init__(self, parent = None):
    QSortFilterProxyModel.__init__(self, parent)
    self.VFS = VFS.Get()  

  def data(self, index, role):
    if index.isValid():
      if role == Qt.CheckStateRole:
        return QVariant()
      else:
        origindex = self.mapToSource(index)
        if origindex.isValid():
          return self.sourceModel().data(origindex, role)
        else:
          return QVariant()
    else:
      return QVariant()

  def filterAcceptsRow(self, row, parent):
     index = self.sourceModel().index(row, 0, parent) 
     if index.isValid():
       node = self.VFS.getNodeFromPointer(index.internalId())
       if node.hasChildren() or node.parent().absolute() == "/" or node.isDir():
	 return True
     return False

  def columnCount(self, parent = QModelIndex()):
     return 1

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

class NodeBrowser(QWidget, DEventHandler):
  def __init__(self, parent):
    QWidget.__init__(self, parent)
    DEventHandler.__init__(self)

    self.mainwindow = parent

    self.getWindowGeometry()

    self.name = self.tr("nodebrowser")
    self.type = "filebrowser"
    self.setObjectName(self.name)

    self.vfs = vfs.vfs()
    self.VFS = VFS.Get()
    #register to event from vfs
    self.VFS.connection(self)
    self.ft = FILETYPE()
    self.env = env.env()	
    self.loader = loader.loader()
    self.lmodules = self.loader.modules
    self.taskmanager = TaskManager()
    self.propertyDialog = Property(self)

    self.parent = parent
    self.icon = None

    self.createSubMenu()
    self.createLayout()
    self.addModel("/")
    self.addProxyModel()
    self.addNodeLinkTreeView()
    self.addNodeView()

    self.addOptionsView()
#    self.browserLayout.addWidget(self.thumbsView)
#    self.browserLayout.addWidget(self.tableView)

#    self.browserLayout.setOpaqueResize(False)

#    siz = self.mainwindow.width() / 3
#    sizelist = [siz, siz * 3]
#    self.browserLayout.setSizes(sizelist)
#    self.browserLayout.setSizes(sizelist)

#    si = self.browserLayout.sizes()
#    for s in si:
#      print s


  #def refresh(self, node):
     #self.thumbsView.model().sourceModel().emit(SIGNAL("refresh"), None)
     #self.tableView.model().sourceModel().emit(SIGNAL("refresh"), None)
     #self.treeModel.emit(SIGNAL("refresh"), node)	

  def getWindowGeometry(self):
    self.winWidth = self.mainwindow.width()


  def Event(self, e):
    self.model.emit(SIGNAL("layoutAboutToBeChanged()"))
    self.model.emit(SIGNAL("layoutChanged()"))
    self.treeModel.emit(SIGNAL("layoutAboutToBeChanged()"))
    self.treeModel.emit(SIGNAL("layoutChanged()"))


  def createLayout(self):
    self.baseLayout = QVBoxLayout(self)
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

  def addProxyModel(self):
    self.proxyModel = QSortFilterProxyModel(self)
    self.proxyModel.setSourceModel(self.model)

  ###### View searhing #####
  def addSearchView(self):
    self.search_model = VfsSearchItemModel(self, True)
    self.treeModel.setRootPath(self.vfs.getnode("/"))

  def addNodeLinkTreeView(self):
    self.treeModel = VFSItemModel(self, True)
    self.treeModel.setRootPath(self.vfs.getnode("/"))
    self.treeProxyModel = NodeTreeProxyModel()
    self.treeProxyModel.setSourceModel(self.treeModel)
    self.treeView = NodeLinkTreeView(self)
    self.treeView.setModel(self.treeProxyModel)

#    self.treeView.setMaximumWidth(self.mainwindow.width() / 3)
    self.browserLayout.addWidget(self.treeView)

    self.browserLayout.setStretchFactor(self.browserLayout.indexOf(self.treeView), 0)

    self.connect(self.treeView, SIGNAL("nodeTreeClicked"), self.nodeTreeDoubleClicked)
#    self.connect(self.treeView, SIGNAL("resizeEvent"), self.treeResized)

  def addNodeView(self):
#    self.nodeView = QStackedLayout(self.browserLayout)
    self.addTableView()
    self.addThumbsView()

  def addTableView(self): 
    self.tableView = NodeTableView(self)
    self.tableView.setModel(self.proxyModel)
    self.tableView.setColumnWidth(0, 200)
    self.tableView.setSortingEnabled(True)
    self.tableView.setSizePolicy(QSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum))
#    self.tableView.setMinimumWidth(self.mainwindow.width() / 3)
    self.browserLayout.addWidget(self.tableView)

    self.browserLayout.setStretchFactor(self.browserLayout.indexOf(self.tableView), 1)

    self.connect(self.tableView, SIGNAL("nodePressed"), self.nodePressed)
    self.connect(self.tableView, SIGNAL("nodeClicked"), self.nodeClicked)
    self.connect(self.tableView, SIGNAL("nodeDoubleClicked"), self.nodeDoubleClicked)
    #self.model.setImagesThumbnails(True)

  def addThumbsView(self):
    self.thumbsView = NodeThumbsView(self)
    self.thumbsView.setModel(self.proxyModel) 
    self.thumbsView.setSizePolicy(QSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum))
#    self.thumbsView.setMinimumWidth(self.mainwindow.width() / 3)
    self.browserLayout.addWidget(self.thumbsView)

    self.browserLayout.setStretchFactor(self.browserLayout.indexOf(self.thumbsView), 1)

#    self.nodeView.addWidget(self.thumbsView)
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
       return self.thumbsView.model().sourceModel()
     elif self.tableView.isVisible():
       return self.tableView.model().sourceModel()
 
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
	 index = self.currentProxyModel().mapToSource(index)
         nodeList.append(self.VFS.getNodeFromPointer(index.internalId()))
     return nodeList

  def currentNode(self):
     index = self.currentView().selectionModel().currentIndex()
     if index.isValid():
	 index = self.currentProxyModel().mapToSource(index)
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
      print node.absolute(), node.parent().absolute()
      self.currentModel().setRootPath(node.parent().parent())

  def nodeClicked(self, mouseButton, node, index = None):
     if mouseButton == Qt.LeftButton:
         if self.nodeViewBox.propertyTable.isVisible():
            self.nodeViewBox.propertyTable.fill(node)
     if mouseButton == Qt.RightButton:
       if node.hasChildren() or node.isDir():
         self.opendirasnewtab.setEnabled(True)
       else:
         self.opendirasnewtab.setEnabled(False)
       self.submenuFile.popup(QCursor.pos())
       self.submenuFile.show()       

  def nodeTreeDoubleClicked(self, mouseButton, node, index = None):
     if self.currentView().enterInDirectory:
       if node.hasChildren() or node.isDir():
	 self.currentModel().setRootPath(node) 

  def nodeDoubleClicked(self, mouseButton, node, index = None):
     if self.currentView().enterInDirectory:
       if node.hasChildren() or node.isDir():
	 self.currentModel().setRootPath(node) 
       else:
	 self.openDefault(node)
     else:  
         self.openDefault(node)

  def sizeChanged(self, string):
     if string == "Small":
       self.thumbsView.setIconSize(64, 64)
     elif string == "Medium":
       self.thumbsView.setIconSize(96, 96)
     elif string == "Large":
       self.thumbsView.setIconSize(128, 128)

  def openDefault(self, node = None):
     if not node:
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
       self.taskmanager.add("hexadecimal", arg, ["thread", "gui"])       
 
  def createSubMenu(self):
     self.extractor = Extractor(self.parent)
     self.connect(self.extractor, SIGNAL("filled"), self.launchExtract)
     self.submenuFile = QMenu()
     self.submenuFile.addAction(QIcon(":exec.png"),  "Open", self.openDefault, "Open")
     ####
     self.opendirasnewtab = QAction("Open in new tab", self)
     self.opendirasnewtab.setEnabled(False)
     self.submenuFile.addAction(self.opendirasnewtab)
     self.connect(self.opendirasnewtab, SIGNAL("triggered()"), self.openAsNewTab)
     ###
     self.menu = {}
     self.menu["Modules"] = self.submenuFile.addMenu(QIcon(":exec.png"),  "Open With")
     self.menuTags = MenuTags(self, self.parent, self.currentNodes)
     self.submenuFile.addSeparator()
     self.submenuFile.addAction(QIcon(":hexedit.png"), "Hex viewer", self.launchHexedit, "Hex viewer")
     self.submenuFile.addAction(QIcon(":extract.png"),  "Extract", self.extractNodes, "ExtractNode")
     self.submenuFile.addSeparator()
#     self.submenuFile.addAction(QIcon(":info.png"),  "Property", self.launchProperty, "Property")

  def openAsNewTab(self):
    node = self.currentNode()
    self.mainwindow.addBrowser(node)

  def launchHexedit(self):
     nodes = self.currentNodes()
     for node in nodes:
        arg = self.env.libenv.argument("gui_input")
        arg.thisown = 0
        arg.add_node("file", node)
        self.taskmanager.add("hexadecimal", arg, ["thread", "gui"])

  def launchProperty(self, node = None):
       if not node:
         node = self.currentNode()
         if not node:
           return
       self.propertyDialog.fillInfo(node, node.parent().children())
       self.propertyDialog.exec_()
       self.propertyDialog.removeAttr()
 
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

