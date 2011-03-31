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

HNAME = 0
HSIZE = 1
HMODULE = 2

HCHANGED = 3
HMODIFIED = 4
HACCESSED = 5

pixmapCache = QPixmapCache()
pixmapCache.setCacheLimit(61440)

class ImageThumb():
  def __init__(self):
    pass

  def getImage(self, type, node, index):
    buff = ""
    tags = None
    img = QImage()
    if type.find('jpeg') != -1:
      try:
        buff = self.getThumb(node)
        load = img.loadFromData(buff, type)
	if load == False:
	 buff = ""
      except IOError:
        buff = ""
    if not len(buff):
      try:
        f = node.open()
        buff = f.read()
        f.close()
        load = img.loadFromData(buff)
      except IOError:
        load = False
    if load:
      img = img.scaled(QSize(128, 128), Qt.KeepAspectRatio, Qt.FastTransformation)
      return img
    return None

  def getThumb(self, node):
     buff = ""
     if node.size() > 6:
       try:
         file = node.open()
         head = file.find("\xff\xd8\xff", 3, "", 3)
         if head > 0 and head < node.size():
           foot = file.find("\xff\xd9", 2, "", long(head))
           if foot > 0 and foot < node.size():
             file.seek(head)
             buff = file.read(foot + 2 - head)
         file.close()
       except IOError:
         return ""
     return buff

class TypeWorker(QThread):
  def __init__(self, *args):
    QThread.__init__(self)
    self.typeQueue = Queue()
    self.regImage = re.compile("(JPEG|JPG|jpg|jpeg|GIF|gif|bmp|BMP|png|PNG|pbm|PBM|pgm|PGM|ppm|PPM|xpm|XPM|xbm|XBM).*", re.IGNORECASE)
    self.typeQueue = []
    self.setUniq = set()
    self.qmutex = QMutex()
    self.qsem = QSemaphore()

  def enqueue(self, parent, index, node):
    self.qmutex.lock()
    if long(node.this) not in self.setUniq:
       self.typeQueue.insert(0, (parent, index, node))
       self.setUniq.add(long(node.this))
       self.qsem.release()
    self.qmutex.unlock()

  def clear(self):
    self.qmutex.lock()
    self.typeQueue = []
    self.setUniq.clear()
    self.qsem.acquire(self.qsem.available())
    self.qmutex.unlock()

  def get(self):
    self.qsem.acquire()
    self.qmutex.lock()
    res = self.typeQueue.pop()
    self.setUniq.remove(long(res[2].this))
    self.qmutex.unlock()
    return res

  def isImage(self, ftype):
    res = self.regImage.search(ftype)
    return res

  def run(self):
     count = 0
     while True:
       (parent, index, node) = self.get()
       if node.size():
         ftype = str(node.dataType())
         if parent.imagesthumbnails and self.isImage(ftype):
           thumb = ImageThumb()
           img = thumb.getImage(ftype, node, index)
           if img:
             parent.emit(SIGNAL('dataImage'), index, node, img)

typeWorker = TypeWorker()
typeWorker.start()


class VFSItemModel(QAbstractItemModel, EventHandler):
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

class TreeModel(QStandardItemModel, EventHandler):
  """
  This class, inheriting QStandardItemModel. This model is used for the QTreeView on the left of
  DFF gui (the tree view of the nodes). In this view only directories and nodes with children
  are displayed (files does not appear).

  QStandardItemModel's are used in combination with QStandrdItem's. The root item, which is
  invisible, is returned by the method QStandardItemModel.invisibleRootItem(). Once expended 
  in the QTreeView, each directory is represented by a QStandardItem, where the associated data
  with the role `Qt.UserRole + 1` is a pointer on the node.

  Rows are inserted in the model and QStandardItem created by the QTreeView only when users click
  on the '+' button to exand a node.

  More documentation on QStandardItemModel and QStandardItem models can respectively be found at :

   * http://www.riverbankcomputing.co.uk/static/Docs/PyQt4/html/qstandarditemmodel.html
   * http://www.riverbankcomputing.co.uk/static/Docs/PyQt4/html/qstandarditem.html

  """
  numberPopulated = QtCore.pyqtSignal(int)  
  def __init__(self, __parent = None, event=False, fm = False):
    """
    Model constructor. Create the default QStandardItem's for the default nodes.
    """
    QStandardItemModel.__init__(self, __parent)
    EventHandler.__init__(self)
    self.__parent = __parent
    self.VFS = VFS.Get()

    # init translation
    self.translation()

    # creating qstandarditem for the default nodes (the four displayed nodes when dff is launched)
    self.root_item = self.invisibleRootItem()
    tmp = self.VFS.GetNode("/").children()
    item_list = []
    for i in tmp:
      node_item = QStandardItem(i.name())
      node_item.setData(QVariant(long(i.this)), Qt.UserRole + 1)
      node_item.setData(QVariant(False), Qt.UserRole + 2)
      item_list.append(node_item)
    if len(item_list):
      self.root_item.appendRows(item_list)

    if event:
      self.VFS.connection(self)

  def nodeClicked(self, mouseButton, node, index = None):
    """
    Unused
    """
    pass

  def setRootPath(self, node, kompleter = None):
    """
    Set the root path of the model.
    """
    if node == None:
      return
    typeWorker.clear()
    self.rootItem = node
    if kompleter == None:
      self.emit(SIGNAL("rootPathChanged"), node)
    self.reset()

  def headerData(self, section, orientation, role=Qt.DisplayRole):
    """
    \reimp

    The only column is the `name` column. 

    \return QVariant("Name") if the role is Qt.DisplatRole, an invalid QVariant otherwise.
    """
    if role != Qt.DisplayRole:
      return QVariant()
    else:
      return QVariant(self.nameTr)

  def data(self, index, role):
    """
    \reimp

    Nodes' pointers are encapsulated in QStandardItem (role : Qt.UserRole + 1). Most
    of the data can only be retrieved only if the node is retrieved:

    * The node name
    * The node icon
    * ...

    To do so, the TreeModel.data() method calls the QStandardItemModel.data() method by passing
    the `index` parameter and `Qt.UserRole + 1` or `Qt.UserRole + 2` to it. In the second case, it
    retrieves a boolean used to know if the node is already expended and returns directly.

    \param index the index of the data we want to get
    \param role the role of the data we want to retrieve

    \return a QVariant containing the data, or an invalid QVariant if the data could not be retrieved.
    """

    # Qt.UserRole + 2 contain a boolean indicating if the node has already been expanded
    # in the tree.
    if role == Qt.UserRole + 2:
      return QStandardItemModel.data(self, index, role)

    # call QStandardItemModel.data method with a Qt.UserRole + 1 to get the pointer on the node
    # (returns a invalid QVariant if the node or the data is None)
    data = QStandardItemModel.data(self, index, Qt.UserRole + 1)
    if not data.isValid():
      return data
    
    # getting the node or returning an invalid QVariant() if the node is not valid
    node = self.VFS.getNodeFromPointer(data.toULongLong()[0])
    if node == None:
      return QVariant()

    # if role == UserRole + 1, it means that the node itself must be returned (the pointer
    # on the node, encapsulated in a QVariant()
    if role == (Qt.UserRole + 1):
      return data

    # in other cases, returns the requires data  : icon, color, etc. or an invalid QVariant()
    # if the role does not correpond to anything.
    if role == Qt.ForegroundRole:
      if node.isDeleted():
        return  QVariant(QColor(Qt.red))
    if role == Qt.DisplayRole :
      return QVariant(node.name())
    if role == Qt.DecorationRole:
      return QVariant(QIcon(node.icon()))
    return QVariant()

  def columnCount(self, parent = QModelIndex()):
    """
    \reimp

    The number of columns of the model, which is always set to `1` in this case.

    \return `1`
    """
    return 1

  def hasChildren(self, parent):
    """
    \return `True` if the index `parent` has at least one child, `False` otherwise.

    When this method returns `False`, the '+' button in the view is not displayed
    anf the corresponding node cannot be expanded.
    
    \warning for convenience, this method always returns `True` for now, so a '+' button is
    displayed for each nodes, even if they do not have any children. 
    """
    if not parent.isValid():
      return True
    else:
      ptr = self.data(parent, Qt.UserRole + 1)
      if ptr == None:
        return False
      node = self.VFS.getNodeFromPointer(ptr.toULongLong()[0])
      if node == None:
        return False
      if node.name() == "/":
        return True
      tmp = node.children()
      for i in tmp:
        if i.isDir() or i.hasChildren():
          return True
    return False

  def flags(self, flag):
    """
    \reimp

    \returns the flag set in the model.
    """
    return (Qt.ItemIsSelectable | Qt.ItemIsEnabled )  

  def Event(self, e):
    """
    Add e.value, which is a Variant containing a Node, in the tree (only if it has children
    or is a directory).

    """
    self.emit(SIGNAL("layoutAboutToBeChanged()"))
    value = e.value
    node = value.value()
    if node != None and (node.hasChildren() or node.isDir()):
      if node.parent().name() == "/":
        item = QStandardItem(node.name())
        item.setData(long(node.this), Qt.UserRole + 1)
        item.setData(False, Qt.UserRole + 2)
        self.root_item.appendRow(item)
      else:
        self.getItemByName(node.parent().absolute(), node.parent(), node)
    self.emit(SIGNAL("layoutChanged()"))

  def getItemByName(self, name, parent, new_node):
    """
    Returns a standard item according to a node name, or none if
    no node with the name `name` is found.
    """
    l = name.split("/")

    node = None
    item = self.root_item
    l.pop(0) # remove the empty first element of the list

    found = False
    for i in l:
      # iter on the list until the qstandarditem associated with node 'i' is found

      found = False
      for j in range(0, item.rowCount()): # find the node in the item children
        tmp_item = item.child(j)
        if tmp_item == None:
          continue
        tmp_index = self.indexFromItem(tmp_item)
        if tmp_index == None:
          continue
        ptr = self.data(tmp_index, Qt.UserRole + 1).toULongLong()[0]
        if ptr == None:
          continue

        node = self.VFS.getNodeFromPointer(ptr)
        if node != None:
          if node.name() == i:
            item = tmp_item
            found = True
            break
          else:
            found = False
        else:
          found = False
      if not found:
        break

    if node == None:
      return

    # add the node in the tree only if its parent is already expended
    if found == False:
      if node.parent().absolute() == parent.absolute():
        new_item = QStandardItem(parent.name())
        new_item.setData(long(parent.this), Qt.UserRole + 1)
        new_item.setData(False, Qt.UserRole + 2)
        item.insertRow(0, new_item)
        item.setData(True, Qt.UserRole + 2)
      elif node.parent().absolute() == parent.parent().absolute():
        new_item = QStandardItem(parent.name())
        new_item.setData(long(parent.this), Qt.UserRole + 1)
        new_item.setData(False, Qt.UserRole + 2)
        item.insertRow(0, new_item)
        item.setData(True, Qt.UserRole + 2)
    else:
      new_item = QStandardItem(new_node.name())
      new_item.setData(long(new_node.this), Qt.UserRole + 1)
      new_item.setData(False, Qt.UserRole + 2)
      item.insertRow(0, new_item)
      item.setData(True, Qt.UserRole + 2)

  def translation(self):
    """
    Used for translating the framework.
    """
    self.nameTr = self.tr('Name')


class CompleterModel(VFSItemModel):
    def __init__(self):
        VFSItemModel.__init__(self)
        self.__absolute = False
        self.currentPath = ""


    def setCurrentPath(self, path):
      self.currentPath = path
      

    def data(self, index, role):
        if not index.isValid():
          return QVariant()
        if index.row() > len(self.node_list) or index.row() < 0:
          return QVariant()
        node = self.node_list[index.row()]
        column = index.column()
        if role == Qt.DisplayRole and index.column() == 0:
          if self.currentPath != "":
            res = node.absolute()[len(self.currentPath):]
          else:
            res = node.absolute()
          return QVariant(res)
        if role == Qt.DecorationRole and column == HNAME:
          return QVariant(QIcon(node.icon()))
        else:
          return QVariant()
