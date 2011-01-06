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
from api.vfs.libvfs import VFS

class NodeViewEvent():
  def __init__(self, parent = None):
   self.enterInDirectory = None 
   self.parent = parent
   self.VFS = VFS.Get()

  def keyReleaseEvent(self, e):
    index = self.currentIndex()
    index = self.model().mapToSource(index)
    if index.isValid():
      node = self.VFS.getNodeFromPointer(index.internalId())
      self.emit(SIGNAL("nodePressed"), e.key(), node)
    self.origView.keyReleaseEvent(self, e)

  def mouseReleaseEvent(self, e):
     index = self.indexAt(e.pos())
     index = self.model().mapToSource(index)
     if index.isValid():
       node = self.VFS.getNodeFromPointer(index.internalId())
       self.emit(SIGNAL("nodeClicked"), e.button(), node)
     self.origView.mouseReleaseEvent(self, e)

  def mouseDoubleClickEvent(self, e):
     index = self.indexAt(e.pos())
     index = self.model().mapToSource(index)
     if index.isValid():
       node = self.VFS.getNodeFromPointer(index.internalId())
       self.emit(SIGNAL("nodeDoubleClicked"), e.button(), node) 
     self.origView.mouseReleaseEvent(self, e)

  def setEnterInDirectory(self, flag):
     self.enterInDirectory = flag  

class NodeThumbsView(QListView, NodeViewEvent):
  def __init__(self, parent):
     QListView.__init__(self, parent)
     self.origView = QListView
     NodeViewEvent.__init__(self, parent)
     width = 64
     height = 64
     self.setIconSize(width, height)
     self.setLayoutMode(QListView.SinglePass)
     self.setViewMode(QListView.IconMode)
     self.setUniformItemSizes(False)
     self.setResizeMode(QListView.Adjust)
     self.setEnterInDirectory(True)
     self.setFlow(QListView.LeftToRight)
     self.setMovement(QListView.Static)
     self.setSelectionMode(QAbstractItemView.ExtendedSelection)
     self.setSelectionBehavior(QAbstractItemView.SelectRows)

  def setIconSize(self, width, height):
    QListView.setIconSize(self, QSize(width, height))
    self.setGridSize(QSize(width + 18, height + 20))

class NodeLinkTreeView(QTreeView):
  def __init__(self, parent):
     QTreeView.__init__(self, parent)
     self.VFS = VFS.Get()
     self.setSelectionMode(QAbstractItemView.SingleSelection)
     self.setSelectionBehavior(QAbstractItemView.SelectItems)
     self.setUniformRowHeights(True)

  def mousePressEvent(self, e):
     index = self.indexAt(e.pos())
     if index.isValid():
       indexWasExpanded = self.isExpanded(index)
       QTreeView.mousePressEvent(self, e)
       if (self.isExpanded(index) == indexWasExpanded):
         index = self.model().mapToSource(index)
         node = self.VFS.getNodeFromPointer(index.internalId())
         self.emit(SIGNAL("nodeTreeClicked"), e.button(), node)

class NodeTreeView(QTreeView, NodeViewEvent):
  def __init__(self, parent):
     QTreeView.__init__(self, parent)
     NodeViewEvent.__init__(self, parent)
     self.origView = QTreeView
     self.setSelectionMode(QAbstractItemView.SingleSelection)
     self.setSelectionBehavior(QAbstractItemView.SelectItems)
     self.setExpandsOnDoubleClick(False)

class NodeTableView(QTableView, NodeViewEvent):
   def __init__(self, parent):
      QTableView.__init__(self, parent)
      self.origView = QTableView
      NodeViewEvent.__init__(self, parent)
      self.setShowGrid(False)
      self.setEnterInDirectory(True)
      self.horizontalHeader().setStretchLastSection(True)
      self.verticalHeader().hide()
      self.setAlternatingRowColors(True)
      self.setSelectionMode(QAbstractItemView.ExtendedSelection)
      self.setSelectionBehavior(QAbstractItemView.SelectRows)
#changer les font ?
