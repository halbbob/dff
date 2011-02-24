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
from api.vfs.libvfs import VFS

class NodeViewEvent():
  def __init__(self, parent = None):
   self.enterInDirectory = None 
   self.parent = parent
   self.VFS = VFS.Get()

  def keyReleaseEvent(self, e):
    #index = self.currentIndex()
    # index = self.model().mapToSource(index)
    #if index.isValid():
    #  node = self.VFS.getNodeFromPointer(index.internalId())
    #  self.emit(SIGNAL("nodePressed"), e.key(), node)
    #self.origView.keyReleaseEvent(self, e)
    pass

  def mouseReleaseEvent(self, e):
     index = self.indexAt(e.pos())
#####
#     index = self.model().mapToSource(index)
     if index.isValid():
       node = self.VFS.getNodeFromPointer(index.internalId())
       self.emit(SIGNAL("nodeClicked"), e.button(), node)
     self.origView.mouseReleaseEvent(self, e)

  def mouseDoubleClickEvent(self, e):
     index = self.indexAt(e.pos())
#####     
#     index = self.model().mapToSource(index)
     if index.isValid():
       node = self.VFS.getNodeFromPointer(index.internalId())
       self.emit(SIGNAL("nodeDoubleClicked"), e.button(), node) 
     self.origView.mouseReleaseEvent(self, e)

  def setEnterInDirectory(self, flag):
     self.enterInDirectory = flag  

class NodeThumbsView(QListView, NodeViewEvent):
  def __init__(self, parent):
     super(NodeThumbsView, self).__init__(parent)
     self.origView = QListView
     NodeViewEvent.__init__(self, parent)
     width = 64
     height = 64
     self.setIconGridSize(width, height)
     self.setLayoutMode(QListView.Batched)
     self.setViewMode(QListView.IconMode)

     self.setResizeMode(QListView.Adjust)
     #elf.setResizeMode(QListView.Fixed)
     self.setEnterInDirectory(True)
     self.setFlow(QListView.LeftToRight)
     self.setMovement(QListView.Static)
     self.setSelectionMode(QAbstractItemView.ExtendedSelection)
     self.setSelectionBehavior(QAbstractItemView.SelectRows)

     self.setBatchSize(10) #augmenter ? 
     self.setWordWrap(False)
     self.setTextElideMode(1)	
     self.setUniformItemSizes(True)
     self.setWrapping(True)

  def setIconGridSize(self, width, height):
     self.setIconSize(QSize(width, height))
     self.setGridSize(QSize(width + 18, height + 20))

class DffProgressBar(QProgressBar):
  """
  This progress bar is displayed in the node tree view when users expand a node
  containing loads of children.
  """
  def __init__(self, parent = None):
    QProgressBar.__init__(self, parent)
    self.max = 0
    self.setVisible(False)
 
  def rowsAdded(self, nb_pop):
    """
    Slot connected to the TreeModel.numberPopulated(int) signal. It updates the value of
    the bar by calling QProgressBar.value()
    """
    self.show()
    self.setRange(1, self.max)
    self.setValue(nb_pop)

    # when value() reaches maximum(), it means that all nodes are displayed, so we reset
    # the bar, hide it and disconnect the signal.
    if self.value() == self.maximum():
      self.disconnect(self.parent().model().sourceModel(), SIGNAL("numberPopulated(int)"), self.rowsAdded)
      self.hide()
      self.parent().model().nb_pop = 0

class NodeLinkTreeView(QTreeView):
  """
  This view is used to display the node tree view (in the left part of the Gui).

  When a node of the QTreeView is expanded, it can freeze the gui if the node contains
  loads of chilfren, so a progress bar is displayed in those cases.
  """
  def __init__(self, parent):
     QTreeView.__init__(self)
     self.VFS = VFS.Get()
     self.setSelectionMode(QAbstractItemView.SingleSelection)
     self.setSelectionBehavior(QAbstractItemView.SelectItems)
     self.setUniformRowHeights(True)
     self.setSortingEnabled(False)
     self.wait_until_it_crashes = DffProgressBar(self)
     self.val = 0

  def mousePressEvent(self, e):
    """
    \reimp

    Nodes are expanded only if users click on '+' buttons the tree. If they click on the 
    icons or names of nodes, the node is not expanded.

    Overload of the QTreeView.mousePressEvent() event handler. If the user
    clicked on the '+' of the view to expand a node, call the NodeLinkTreeView.dispProgressBar()
    method. Otherwise call the QTreeView.mousePressEvent() event handler.

    \param e the event
    """
    index = self.indexAt(e.pos())
    if index.isValid():
      # caclculate click coordinate to determine if the click occurs on the '+' button
      self.model().sourceModel().nb_pop = 0

      v_rect = self.visualRect(index)
      indentation = v_rect.x() - self.visualRect(self.rootIndex()).x()
      rect = QRect(self.header().sectionViewportPosition(0) + indentation - self.indentation(), \
                     v_rect.y(), self.indentation(), v_rect.height())
      if rect.contains(e.pos()) and self.model().hasChildren(index):
        self.dispProgressBar(index)
      QTreeView.mousePressEvent(self, e)
      idx = self.model().mapToSource(index)
      node = self.VFS.getNodeFromPointer(idx.internalId())
      self.emit(SIGNAL("nodeTreeClicked"), e.button(), node)

  def mouseDoubleClickEvent(self, e):
    """
    \reimp

    When users double-click on a node in the tree view, it expands the double-clicked node.
    To do so, the NodeLinkTreeView.dispProgressBar() method is called.

    \param e the event
    """
    self.nb_pop = 0
    index = self.indexAt(e.pos())
    if index.isValid():
      self.dispProgressBar(index)
      node = self.VFS.getNodeFromPointer(index.internalId())
      self.emit(SIGNAL("nodeDoubleClicked"), e.button(), node)
    QTreeView.mouseDoubleClickEvent(self, e)

  def dispProgressBar(self, idx):
    """
    This method is called when a node is about to be expanded. It initializes and displays
    a QProgressBar which is hidden when the content of the selectionned node has finished
    expanded expanding. This bar is displayed only if the numbner of children of the node
    is superior to 1000.

    \param index the index corresponding to the item we are about to expand.
    """
    # get node
    index = self.model().mapToSource(idx)

    node = self.VFS.getNodeFromPointer(index.internalId())
    if node != None:
      self.model().sourceModel().currentNode = node
      if not self.isExpanded(idx) and node.hasChildren() and node.childCount() > 1000:
        min = 1
        max = node.childCount()

        # set minimum and maximum value (min is 1, if set to 0 it segfaults for a reason
        # I do not understand).
        self.wait_until_it_crashes.max = max
        self.wait_until_it_crashes.setMinimum(min)
        self.wait_until_it_crashes.setMinimum(max)
        self.wait_until_it_crashes.setValue(min)
        self.wait_until_it_crashes.setVisible(True)

        # connect the bar to the TreeModel.numberPopulated(int) signal.
        self.connect(self.model().sourceModel(), SIGNAL("numberPopulated(int)"), self.wait_until_it_crashes.rowsAdded)

  def indexRowSizeHint(self, index):
     return 2

class NodeTreeView(QTreeView, NodeViewEvent):
  def __init__(self, parent):
     QTreeView.__init__(self, parent)
     NodeViewEvent.__init__(self, parent)
     self.origView = QTreeView
     self.setSelectionMode(QAbstractItemView.SingleSelection)
     self.setSelectionBehavior(QAbstractItemView.SelectItems)
     self.setExpandsOnDoubleClick(False)
     self.setUniformRowHeights(True)
     self.setSortingEnabled(False)

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
