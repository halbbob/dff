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
#  Romain Bertholon <rbe@digital-forensic.org>
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

from api.gui.dialog.applymodule import ApplyModule
from api.gui.dialog.extractor import Extractor
from api.gui.widget.nodeview import NodeThumbsView, NodeTableView, NodeTreeView, NodeLinkTreeView 
from api.gui.widget.propertytable import PropertyTable
from api.gui.model.vfsitemmodel import ListNodeModel

from ui.gui.utils.menu import MenuTags, MenuRelevant
from ui.gui.resources.ui_nodebrowser import Ui_NodeBrowser

modulePriority = {} 

class SearchNodeBrowser(QWidget, EventHandler, Ui_NodeBrowser):
  def __init__(self, parent):
    super(QWidget, self).__init__()
    EventHandler.__init__(self)
    self.setupUi(self)

    self.mainwindow = parent.parent.parent.parent
    self.model = ListNodeModel(self)
    self.name = self.windowTitle()
    self.type = "filebrowser"
    self.setObjectName(self.name)

    self.vfs = vfs.vfs()
    self.VFS = VFS.Get()
    self.loader = loader.loader()
    self.lmodules = self.loader.modules
    self.taskmanager = TaskManager()

    self.parent = parent
    self.icon = None

    self.createSubMenu()
    self.createLayout()

  def Event(self, e):
    self.model.emit(SIGNAL("layoutAboutToBeChanged()")) 
    self.model.emit(SIGNAL("layoutChanged()"))

  def getWindowGeometry(self):
    self.winWidth = self.mainwindow.width()

  def createLayout(self):
    self.baseLayout = QVBoxLayout(self)
    self.baseLayout.setMargin(0)
    self.baseLayout.setSpacing(0)
    self.browserLayout = QSplitter(self)
    self.baseLayout.insertWidget(0, self.browserLayout)
    self.baseLayout.setStretchFactor(self.browserLayout, 1)

  def addNodeView(self):
    self.addTableView()
    self.addThumbsView()

  def addTableView(self): 
    self.tableView = NodeTableView(self)
    self.tableView.horizontalHeader().setStretchLastSection(True)
    self.tableView.setColumnWidth(0, 200)
    self.tableView.setSizePolicy(QSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum))
    self.browserLayout.addWidget(self.tableView)

    self.browserLayout.setStretchFactor(self.browserLayout.indexOf(self.tableView), 1)

    self.connect(self.tableView, SIGNAL("nodePressed"), self.nodePressed)
    self.connect(self.tableView, SIGNAL("nodeClicked"), self.nodeClicked)
    self.connect(self.tableView, SIGNAL("nodeDoubleClicked"), self.nodeDoubleClicked)
    self.connect(self.tableView, SIGNAL(""), self.selectAttr)

  def applyModule(self, modname, modtype, selected):
      appMod = ApplyModule(self)
      appMod.openApplyModule(modname, modtype, selected)

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
      return self.tableView.model() 
 
  def currentView(self):
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
      self.parent.xtd_attr.fill(node)
      self.mainwindow.emit(SIGNAL("previewUpdate"), node)	

  def nodeClicked(self, mouseButton, node, index = None):
     if mouseButton == Qt.LeftButton:
	 self.mainwindow.emit(SIGNAL("previewUpdate"), node)
     if mouseButton == Qt.RightButton:
       self.menuRelevant = MenuRelevant(self, self, node)
       if node.hasChildren() or node.isDir():
         self.actionOpen_in_new_tab.setEnabled(True)
       else:
         self.actionOpen_in_new_tab.setEnabled(False)
       self.submenuFile.popup(QCursor.pos())
       self.submenuFile.show()
     self.parent.xtd_attr.fill(node)

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
        self.openAsNewTab()
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
     mods.reverse()	
     if len(mods):
       for mod in mods:
          if "Viewers" in self.lmodules[mod].tags:
	    break
       try:
         priority = modulePriority[mod]
       except KeyError:
         modulePriority[mod] = 0
         priority = 0
       if not priority: 
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
       errnodes = ""
       if node.size():
         conf = self.lmodules["hexadecimal"].conf
         try:
           arg = conf.generate({"file": node})
           self.taskmanager.add("hexadecimal", arg, ["thread", "gui"])
         except RuntimeError:
           errnodes += node.absolute() + "\n"
       else:
         errnodes += node.absolute() + "\n"
       if len(errnodes):
         msg = QMessageBox(self)
         msg.setWindowTitle(self.tr("Empty files"))
         msg.setText(self.tr("the following nodes could not be opened with Hex viewer because they are either empty or folders\n"))
         msg.setIcon(QMessageBox.Warning)
         msg.setDetailedText(errnodes)
         msg.setStandardButtons(QMessageBox.Ok)
         ret = msg.exec_()
 

  def createSubMenu(self):
     self.extractor = Extractor(self.parent)
     self.connect(self.extractor, SIGNAL("filled"), self.launchExtract)
     self.submenuFile = QMenu()
     self.submenuFile.addAction(self.actionOpen)
     self.connect(self.actionOpen, SIGNAL("triggered()"), self.openDefault)
     self.submenuFile.addAction(self.actionOpen_in_new_tab)
     self.connect(self.actionOpen_in_new_tab, SIGNAL("triggered()"), self.openAsNewTab)
     self.submenuRelevant = self.submenuFile.addMenu(self.actionRelevant_module.icon(), self.actionRelevant_module.text())
     self.menu = {}
     self.menuModule = self.submenuFile.addMenu(self.actionOpen_with.icon(), self.actionOpen_with.text())
     self.menuTags = MenuTags(self,     self.parent.parent.parent.parent, self.currentNodes)
     self.submenuFile.addSeparator()
     self.submenuFile.addAction(self.actionHex_viewer)
     self.connect(self.actionHex_viewer, SIGNAL("triggered()"), self.launchHexedit)
     self.submenuFile.addAction(self.actionExtract)
     self.connect(self.actionExtract, SIGNAL("triggered()"), self.extractNodes)
     self.submenuFile.addSeparator()

  def openAsNewTab(self):
    node = self.currentNode()
    self.parent.parent.parent.parent.addNodeBrowser(node)

  def launchHexedit(self):
     nodes = self.currentNodes()
     conf = self.loader.get_conf("hexadecimal")
     errnodes = ""
     for node in nodes:
       if node.size():
         try:
           arg = conf.generate({"file": node})
           self.taskmanager.add("hexadecimal", arg, ["thread", "gui"])
         except RuntimeError:
           errnodes += node.absolute() + "\n"
       else:
         errnodes += node.absolute() + "\n"
     if len(errnodes):
       msg = QMessageBox(self)
       msg.setWindowTitle(self.tr("Empty files"))
       msg.setText(self.tr("the following nodes could not be opened with Hex viewer because they are either empty or folders\n"))
       msg.setIcon(QMessageBox.Warning)
       msg.setDetailedText(errnodes)
       msg.setStandardButtons(QMessageBox.Ok)
       ret = msg.exec_()

  def extractNodes(self):
     self.extractor.launch(self.currentNodes())

  def launchExtract(self):
     res = self.extractor.getArgs()
     args = {}
     args["files"] = res["nodes"]
     args["syspath"] = str(res["path"])
     args["recursive"] = res["recurse"]
     conf = self.loader.get_conf("extract")
     try:
       margs = conf.generate(args)
       self.taskmanager.add("extract", margs, ["thread", "gui"])
     except RuntimeError:
       pass

  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.retranslateUi(self)
      self.menuModule.setTitle(self.actionOpen_with.text())
      self.submenuRelevant.setTitle(self.actionRelevant_module.text())
      self.model.translation()
    else:
      QWidget.changeEvent(self, event)
