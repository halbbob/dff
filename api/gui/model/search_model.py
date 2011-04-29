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
#  Romain Bertholon <rbe@digital-forensic.org>
# 

from PyQt4.QtCore import SIGNAL, QAbstractItemModel, QModelIndex, QVariant, Qt, QDateTime, QSize, QThread, QMutex, QSemaphore
from PyQt4.QtGui import QColor, QIcon, QImage, QImageReader, QPixmap, QPixmapCache, QStandardItemModel, QStandardItem
from PyQt4 import QtCore

import re

from api.types.libtypes import Variant, vtime
from api.vfs.libvfs import VFS
from api.events.libevents import EventHandler

from Queue import *


class SearchModel(QAbstractItemModel, EventHandler):
  """
  The VFSItemModel, inheriting QAbstractItemModel, is used by views of the node browser.

  Data are fetched directly in the VFS. In QTableView, only two column are always displayed :
  * nodes' names
  * nodes' size

  This is up to users to configure which columns they want to display, according to nodes'
  attributes. The currently selected node's children are storedn in the list self.node_list

  More documentation on QAbstractItemModel() can be found at :
  * http://www.riverbankcomputing.co.uk/static/Docs/PyQt4/html/qabstractitemmodel.html
  """

  def __init__(self, __parent = None, event=False, fm = False):
    """
    Constructor.
    """
    QAbstractItemModel.__init__(self, __parent)
    EventHandler.__init__(self)

    # init root + some values
    self.rootItem = None
    self.__parent = __parent
    self.VFS = VFS.Get()
    self.map = {}
    self.imagesthumbnails = None
    self.connect(self, SIGNAL("dataImage"), self.setDataImage)
    self.translation()

    self.fetchedItems = 0
    self.thumbQueued = {}
    self.fm = fm
    self.fm = False
    self.checkedNodes = set()

    # those list contains nodes' children of the currently selcted node.
    self.node_list = []

    # list of headers the user choosed to display.
    self.header_list = []
    self.type_list = []
    self.disp_module = 0
    self.del_sort = 0

    self.cacheAttr = (None, None)

    # connect the mode to the VFS to receive its events
    if event:
      self.VFS.connection(self)

  def setFilterRegExp(self, regExp):
    return

  def Event(self, e):
    """
    This method is called when an event is emitted by the VFS (when a node is added into the
    VFS for example, and the view needs to be redrawed).
    """
    parent = self.rootItem
    if parent != None:
      self.node_list = parent.children()

    # emit signals to redraw the gui
    self.emit(SIGNAL("layoutAboutToBeChanged()"))
    self.emit(SIGNAL("layoutChanged()"))

  def setHeaderData(self, section, orientation, value, role):
    """
    \reimp

    Add a header data into the header. Emit a `layoutAboutToBeChanged` signal before adding the header
    and `layoutChanged` once it is done.
    """
    self.emit(SIGNAL("layoutAboutToBeChanged()"))
    QAbstractItemModel.setHeaderData(self, section, orientation, value, role)
    self.emit(SIGNAL("layoutChanged()"))

  def setDataImage(self, index, node, image):
     pixmap = QPixmap().fromImage(image)
     pixmapCache.insert(str(node.this), pixmap)
     self.__parent.currentView().update(index)

  def imagesThumbnails(self):
     return self.imagesthumbnails

  def setRootPath(self, node, kompleter = None):
    """
    Set the path of the root node.
    """
    self.fetchedItems = 0
    typeWorker.clear()
    self.rootItem = node
    if node != None:
      self.sort(HNAME, Qt.AscendingOrder)
    if kompleter == None:
      self.emit(SIGNAL("rootPathChanged"), node)
    self.reset()

  def qMin(self, x, y):
    """
    Return `x` if it inferior to `y`, `y` otherwise.
    """
    if x < y:
      return x
    else:
      return y

  def rowCount(self, parent):
    """
    \returns the number of children of lines of the index `parent`.
    """
    return len(self.node_list)

  def headerData(self, section, orientation, role=Qt.DisplayRole):
    """
    \reimp

    \return the header data which role is `role`, or an invalid QVariant() if the data could
    not be fetched.
    """

    if role != Qt.DisplayRole:
      return QVariant()
    nb_s = section - 2 - self.disp_module - self.del_sort
    if orientation == Qt.Horizontal:
      if section == HNAME:
        return QVariant(self.nameTr)
      elif section == HSIZE:
        return QVariant(self.sizeTr)
      elif (self.disp_module != 0) and (section == HMODULE):
        return QVariant(self.moduleTr)
      elif (self.del_sort != 0):
        if (self.disp_module != 0):
          if (section == (HMODULE + 1)):
            return QVariant(self.deletedTr)
        elif section == HMODULE:
          return QVariant(self.deletedTr)
      if nb_s >= (len(self.header_list) + len(self.type_list)):
        return QVariant()
      elif nb_s >= len(self.header_list):
        return QVariant(self.type_list[nb_s - len(self.header_list)])
      else:
        return QVariant(self.header_list[nb_s])

  def data(self, index, role):
    """
    \reimp

    Data which can be fetched differs from one view to another and also depends on users configuration.
    Each nodes' attributes can be displayed in views, or hidden, depending on what users want to
    display. The only two columns always displayed are node's name and nodes' size (`HNAME` and `HSIZE`
    columns).

    The mand types of informations that can be displayed, in addition on names and sizes, are :
    * the name of the module who generated the node
    * the MAC time of the nodes (if any)
    * the mimi-type of the node
    * all dynamic extended attributes of the node.
    * a flag indicating if the node is deleted or not

    Sorting can be performed on all the data by clicking in the correponding header.

    \param index the index where the data is located
    \param role the role of the data
    
    \return the data which index is `index` and role is `role`, or an invalid QVariant if
    the date is invalid.
    
    """
    if not index.isValid():
      return QVariant()
    if index.row() > len(self.node_list) or index.row() < 0:
      return QVariant()
    node = self.node_list[index.row()]
    column = index.column()
    if role == Qt.DisplayRole :
      # return name, size and eventually module columns
      if column == HNAME:
        return QVariant(node.name())
      if column == HSIZE:
        return QVariant(node.size())
      if (self.disp_module != 0) and (column == HMODULE):
        return QVariant(node.fsobj().name)
      elif (self.del_sort != 0):
        if (self.disp_module != 0):
          if (column == (HMODULE + 1)):
            return QVariant(node.isDeleted())
        elif column == HMODULE:
          return QVariant(node.isDeleted())

      # return attributes and type columns
      try :
        nb_c = column - 2 - self.disp_module - self.del_sort
        if nb_c >= (len(self.header_list) + len(self.type_list)):
          return QVariant() # index error
        elif nb_c >= len(self.header_list): # the data is a dataType
          type = self.type_list[nb_c - len(self.header_list)]
          possible_type = node.dataType().value()
          return QVariant(possible_type[str(type)].value())
        else:
          if self.cacheAttr[0] != long(node.this): 
            self.cacheAttr = (long(node.this), node.fsoAttributes())
          attr = self.cacheAttr[1]
          value = attr[str(self.header_list[nb_c])]
          val = value.value()
          if val == None:
            return QVariant(" N / A ")
          if value.type() == 13:
            return QVariant(QDateTime(val.get_time()))
          else:
	    return QVariant(val) 
      except IndexError:
        return QVariant()
      return QVariant()
    
    # returns data corresponding to the role passed in parameter to data() method (icon, background, 
    # etc.)
    if role == Qt.ForegroundRole:
      if column == 0:
        if node.isDeleted():
          return  QVariant(QColor(Qt.red))
    if role == Qt.DecorationRole:
      if column == HNAME:
	if not self.imagesthumbnails:
          return QVariant(QIcon(node.icon()))
        else:
            mtype = str(node.dataType())
            if mtype.find("broken") != -1:
              return QVariant(QIcon(":file_broken.png"))
            pixmap = pixmapCache.find(str(node.this))
            if pixmap:
                return QVariant(QIcon(pixmap))
            elif typeWorker.isImage(mtype):
              typeWorker.enqueue(self, index, node)
              return QVariant(QIcon(":file_temporary.png"))
            return QVariant(QIcon(node.icon()))
    if role == Qt.CheckStateRole:
      if column == HNAME:
	if (long(node.this), 0) in self.checkedNodes:
	  if node.hasChildren():
	    return Qt.PartiallyChecked
          else:
   	    return Qt.Checked
	elif (long(node.this), 1) in self.checkedNodes:
   	    return Qt.Checked
        else:
	    return Qt.Unchecked
    return QVariant()

  def setImagesThumbnails(self, flag):
    """
    Set the image thumbnail.
    """
    self.imagesthumbnails = flag

  def columnCount(self, parent = QModelIndex()):
    """
    \reimp

    This number is variable, depending on the configuration.

    \return the number of displayed columns (at least 2, name and size columns)
    """

    # 2 is for columns names and sizes
    return len(self.header_list) + 2 + len(self.type_list) \
        + self.disp_module + self.del_sort

  def index(self, row, column, parent = QModelIndex()):
    """
    \reimp

    Get the index located at row `row` and column `column`, which parent is `parent`. Create the index
    if it does note exist by calling QAbstractItemModel.createIndex()
    
    \param row the row where the index should be located.
    \param column the column where the index should be located.
    \param parent the parent of the index (invalid QModelIndex by default, corresponding to root node).

    \return the index, or an invalid index if an error occured.
    """
    if not self.hasIndex(row, column, parent):
      return QModelIndex()
    if parent.isValid():
      parentItem = self.VFS.getNodeFromPointer(parent.internalId())
    else:
      parentItem = self.rootItem
    if row < len(self.node_list):
      childItem = self.node_list[row]
    else:
      return QModelIndex()
    index = self.createIndex(row, column, long(childItem.this))
    return index

  def parent(self, index):
    """
    \reimp

    \return the parent index of `index` or an invalid QModelIndex if an erroc occurs.
    """
    if not index.isValid():
      return QModelIndex()
    childItem = self.VFS.getNodeFromPointer(index.internalId())
    parentItem = childItem.parent()
    if parentItem.this == self.rootItem.this:
      return QModelIndex()
    index = self.createIndex(parentItem.at() , 0, long(parentItem.this))
    return index

  def hasChildren(self, parent):
    """
    \reimp

    \return `True` if index `parent` has at least one child, `False` the otherwise.
    """
    if not parent.isValid():
      self.parentItem = self.rootItem
      return self.rootItem.hasChildren()
    else:
      self.parentItem = self.VFS.getNodeFromPointer(parent.internalId())
      return self.parentItem.hasChildren()

  def setData(self, index, value, role):
    """
    \reimp

    Set the data which value is `value` at index `index` with role `role`.

    \return `True` if no error occured, `False` otherwise.
    """
    if not index.isValid():
      return QVariant()
    if role == Qt.CheckStateRole:
      column = index.column()
      if column == HNAME:
        node = self.VFS.getNodeFromPointer(index.internalId())
        if value == Qt.Unchecked:
          if (long(node.this), 0) in self.checkedNodes:
            self.checkedNodes.remove((long(node.this), 0))
          else:
            self.checkedNodes.remove((long(node.this), 1))	
        elif value == Qt.PartiallyChecked:
          self.checkedNodes.add((long(node.this), 0)) 
        elif value == Qt.Checked:
          if node.hasChildren():
            if (long(node.this), 0) not in self.checkedNodes:
              self.checkedNodes.add((long(node.this), 0))
            else:
              self.checkedNodes.remove((long(node.this), 0))
              self.checkedNodes.add((long(node.this), 1))
          else:
            self.checkedNodes.add((long(node.this) , 1))
    return True #return true if ok 	

  def flags(self, flag):
    """
    \reimp

    \return the Qt.ItemFlags of the model.
    """
    return (Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsTristate | Qt.ItemIsEnabled )

  def dataTypeByKey(self, stype, node):
    try:
	return node.dataType().value()[str(stype)].value()
    except IndexError:
	return None	

  def fsoAttributesByKey(self, stype, node):
    try:
       val = node.fsoAttributes()[stype]
       if isinstance(val.value(), vtime):
	 return val.value().get_time()
       return val
    except IndexError:
       return Variant()

  def sort(self, column, order):
    """
    \reimp

    Overload of the sort method used to sort data in the view, according to a given column.
    It calls the `sorted()` python built-in function, which documentation can be found at :
    * http://wiki.python.org/moin/HowTo/Sorting/

    Emit a `layoutAboutToBeChanged()` signal before sorting, and a `layoutChanged()` signal once
    the sorting is finished. It can a few seconds on important data volumes.

    \param column the column on which the user wants to perform the sorting.
    \param the order in which the user wants to sort (`Qt.DescendingOrder` or `Qt.AscendingOrder`).
    """
    parentItem = self.rootItem
    if parentItem == None:
      return
    children_list = parentItem.children()
    if order == Qt.DescendingOrder:
      Reverse = True
    else:
      Reverse = False
    self.emit(SIGNAL("layoutAboutToBeChanged()"))
    if column == HNAME: # sort by name
      self.node_list = sorted(children_list, key=lambda Node: Node.name(), reverse=Reverse)
      self.emit(SIGNAL("layoutChanged()"))
      return
    elif column == HSIZE: # sort be size
      self.node_list = sorted(children_list, key=lambda Node: Node.size(), reverse=Reverse)
      self.emit(SIGNAL("layoutChanged()"))
      return
    elif (self.disp_module == 1) and (column == HMODULE): # sort by module's name
      self.node_list = sorted(children_list, key=lambda Node: Node.fsobj(), reverse=Reverse)
      self.emit(SIGNAL("layoutChanged()"))
      return
    elif (self.del_sort != 0):
      if (self.disp_module != 0):
        if (column == (HMODULE + 1)): # sort by deleted falg
          self.node_list = sorted(children_list, key=lambda Node: Node.isDeleted(), reverse=Reverse)
          self.emit(SIGNAL("layoutChanged()"))
          return
      elif column == HMODULE: 
        self.node_list = sorted(children_list, key=lambda Node: Node.isDeleted(), reverse=Reverse)
        self.emit(SIGNAL("layoutChanged()"))
        return
    if (column - 2) >= (len(self.header_list) + len(self.type_list)): # default sorting if column is out of range
      self.node_list = sorted(children_list, key=lambda Node: Node.name(), reverse=Reverse)
    elif column - 2 >= len(self.header_list): # sorting on the mime type
      type = self.type_list[column - 2 - len(self.header_list)]
      self.node_list = sorted(children_list, \
                                key= lambda Node: self.dataTypeByKey(str(type), Node), \
                                reverse=Reverse)
    else: # sort on an extended attribute.
      self.node_list = sorted(children_list, \
                              key=lambda Node: self.fsoAttributesByKey(str(self.header_list[column - 2]), Node), \
                              reverse=Reverse)
    self.emit(SIGNAL("layoutChanged()"))

  def translation(self):
    """
    Used for translating the framework.
    """
    self.nameTr = self.tr('Name')
    self.sizeTr = self.tr('Size')
    self.ATimeTr = self.tr('Accessed time')
    self.CTimeTr = self.tr('Changed time')
    self.MTimeTr = self.tr('Modified time')
    self.moduleTr = self.tr('Module')
    self.deletedTr = self.tr('Deleted')
