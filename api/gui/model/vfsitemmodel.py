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

from PyQt4.QtCore import SIGNAL, QAbstractItemModel, QModelIndex, QVariant, Qt, QDateTime, QSize, QThread, QMutex, QSemaphore
from PyQt4.QtGui import QColor, QIcon, QImage, QImageReader, QPixmap, QPixmapCache, QStandardItemModel
from PyQt4 import QtCore

import re
from api.variant.libvariant import Variant
from api.vfs.libvfs import VFS, DEventHandler

from Queue import *

HNAME = 0
HSIZE = 1
HACCESSED = 2
HCHANGED = 3
HMODIFIED = 4
HMODULE = 5

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
    #print "clea() " #!!!! si plusieur browser va clear la liste des autres
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
           else:
	     pass #XXX there is not setStaticAttribute now !
             #val = Variant("broken " + str(ftype))
             #val.thisown = False
             #node.setStaticAttribute("type", val)

typeWorker = TypeWorker()
typeWorker.start()

class TreeModel(QAbstractItemModel):
  def __init__(self, __parent = None, event=False, fm = False):
    QAbstractItemModel.__init__(self, __parent)
    self.__parent = __parent
    self.VFS = VFS.Get()
    self.map = {}
    self.imagesthumbnails = None
    self.connect(self, SIGNAL("dataImage"), self.setDataImage)
    self.fetchedItems = 0
    self.thumbQueued = {}
    self.checkedNodes = set()

  def setDataImage(self, index, node, image):
     pixmap = QPixmap().fromImage(image)
     pixmapCache.insert(str(node.this), pixmap)
     self.__parent.currentView().update(index)

  def setRootPath(self, node, kompleter = None):
    self.rootChildCount = node.childCount()
    self.fetchedItems = 0
    typeWorker.clear()
    self.rootItem = node
    if kompleter == None:
      self.emit(SIGNAL("rootPathChanged"), node)
    self.reset()

  def rowCount(self, parent):
    if not parent.isValid():
      parentItem = self.rootItem
    else:
      parentItem = self.VFS.getNodeFromPointer(parent.internalId())
    return parentItem.childCount()

  def headerData(self, section, orientation, role=Qt.DisplayRole):
    if role != Qt.DisplayRole:
      return QVariant()
    else:
      return QVariant(self.tr('Name'))

  def data(self, index, role):
    if not index.isValid():
      return QVariant()
    node = self.VFS.getNodeFromPointer(index.internalId())
    column = index.column()
    if role == Qt.ForegroundRole:
      if column == 0:
        if node.isDeleted():
          return  QVariant(QColor(Qt.red))
    if role == Qt.DisplayRole :
      return QVariant(node.name())
    if role == Qt.DecorationRole:
      if column == HNAME:
        if not node.hasChildren():
          if node.isDir():
            return QVariant(QIcon(":folder_128.png"))
          if not node.size():
            return QVariant(QIcon(":folder_empty_128.png"))
          return QVariant(QIcon(":folder_empty_128.png"))
        else:
          if node.size() != 0:
	    return QVariant(QIcon(":folder_documents_128.png"))
          else:
	    return QVariant(QIcon(":folder_128.png"))
    return QVariant()

  def columnCount(self, parent = QModelIndex()):
     return 1

  def index(self, row, column, parent = QModelIndex()):
    if not self.hasIndex(row, column, parent):
      return QModelIndex()
    if parent.isValid():
      parentItem = self.VFS.getNodeFromPointer(parent.internalId())
    else:
      parentItem = self.rootItem
    childItem = parentItem.children()[row]
    index = self.createIndex(row, column, long(childItem.this))
    return index

  def parent(self, index):
    if not index.isValid():
      return QModelIndex()
    childItem = self.VFS.getNodeFromPointer(index.internalId())
    parentItem = childItem.parent()
    if parentItem.this == self.rootItem.this:
      return QModelIndex()
    children = parentItem.parent().children()
    index = self.createIndex(parentItem.at() , 0, long(parentItem.this))
    return index

  def hasChildren(self, parent):
    self.parentItem = self.VFS.getNodeFromPointer(parent.internalId())
    if self.parentItem == None :
      return self.rootItem.hasChildren()
    return self.parentItem.hasChildren()

  def setData(self, index, value, role):
     if not index.isValid():
       return False
     if role == Qt.CheckStateRole:
       column = index.column()
       if column == HNAME:
    	 node = self.VFS.getNodeFromPointer(index.internalId())
         if node == None:
           return False
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
     return (Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsTristate | Qt.ItemIsEnabled )  

  #def Event(self, e):
    #self.emit(SIGNAL("layoutAboutToBeChanged()"))
    #self.emit(SIGNAL("layoutChanged()"))


class VFSItemModel(QAbstractItemModel, DEventHandler):
  def __init__(self, __parent = None, event=False, fm = False):
    QAbstractItemModel.__init__(self, __parent)
    DEventHandler.__init__(self)

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
    self.node_list = []
    self.header_list = []
    self.cacheAttr = (None, None)

    self.VFS.connection(self)

  def Event(self, e):
    parent = self.rootItem
    if parent != None:
      self.node_list = parent.children()
    self.emit(SIGNAL("layoutAboutToBeChanged()"))
    self.emit(SIGNAL("layoutChanged()"))

  def setDataImage(self, index, node, image):
     pixmap = QPixmap().fromImage(image)
     pixmapCache.insert(str(node.this), pixmap)
     self.__parent.currentView().update(index)

  def imagesThumbnails(self):
     return self.imagesthumbnails

  def setRootPath(self, node, kompleter = None):
    self.fetchedItems = 0
    typeWorker.clear()
    self.rootItem = node
    self.sort(HNAME, Qt.AscendingOrder)
    if kompleter == None:
      self.emit(SIGNAL("rootPathChanged"), node)
    self.reset()

  def qMin(self, x, y):
    if x < y:
      return x
    else:
      return y

  def rowCount(self, parent):
    return len(self.node_list)
   # return self.fetchedItems

  def headerData(self, section, orientation, role=Qt.DisplayRole):
    if role != Qt.DisplayRole:
      return QVariant()
    if orientation == Qt.Horizontal:
      if section == HNAME:
        return QVariant(self.nameTr)
      elif section == HSIZE:
        return QVariant(self.sizeTr)
      elif (section - 2) > len(self.header_list):
        return QVariant()
      else:
        return QVariant(self.header_list[section - 2])

# de canFetchMore(self, parent):
      # if self.fetchedItems < len(self.node_list):
      # return True
      # return False

      # def fetchMore(self, parent):
#    remainder = len(self.node_list) - self.fetchedItems
#    itemsToFetch = self.qMin(50, remainder)
#    self.beginInsertRows(parent, self.fetchedItems, self.fetchedItems + itemsToFetch - 1)
#    self.fetchedItems += itemsToFetch
#    self.endInsertRows()

  def data(self, index, role):
    if not index.isValid():
      return QVariant()
    if index.row() > len(self.node_list) or index.row() < 0:
      return QVariant()
    node = self.node_list[index.row()]
    column = index.column()
    if role == Qt.DisplayRole :
      if column == HNAME:
        return QVariant(node.name())
      if column == HSIZE:
        return QVariant(node.size())
      try :
        if column - 2 > len(self.header_list):
          return QVariant()
	if self.cacheAttr[0] != long(node.this): 
   	  self.cacheAttr = (long(node.this), node.fsoAttributes())
  	attr = self.cacheAttr[1]
        value = attr[str(self.header_list[column - 2])]
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
    self.imagesthumbnails = flag

  def columnCount(self, parent = QModelIndex()):
    return len(self.header_list) + 2 #2 is for columns names and sizes

  def index(self, row, column, parent = QModelIndex()):
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
    if not index.isValid():
      return QModelIndex()
    childItem = self.VFS.getNodeFromPointer(index.internalId())
    parentItem = childItem.parent()
    if parentItem.this == self.rootItem.this:
      return QModelIndex()
    index = self.createIndex(parentItem.at() , 0, long(parentItem.this))
    return index

  def hasChildren(self, parent):
    if not parent.isValid():
	self.parentItem = self.rootItem
        return self.rootItem.hasChildren()
    else:
       self.parentItem = self.VFS.getNodeFromPointer(parent.internalId())
       return self.parentItem.hasChildren()

  def setData(self, index, value, role):
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
     return (Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsTristate | Qt.ItemIsEnabled )  

  def sort(self, column, order):
    """
    Overload of the sort method.
    """
    parentItem = self.rootItem
    if parentItem == None:
      return
    self.emit(SIGNAL("layoutAboutToBeChanged()"))
    children_list = parentItem.children()
    if order == Qt.DescendingOrder:
      Reverse = True
    else:
      Reverse = False
    if column == HNAME:
      self.node_list = sorted(children_list, key=lambda Node: Node.name(), reverse=Reverse)
    elif column == HSIZE:
      self.node_list = sorted(children_list, key=lambda Node: Node.size(), reverse=Reverse)
    elif column == HMODULE:
      self.node_list = sorted(children_list, key=lambda Node: Node.fsobj(), reverse=Reverse)
    elif column - 2 <= len(self.header_list):
      self.node_list = sorted(children_list, \
                              key=lambda Node: Node.dynamicAttributes(str(self.header_list[column - 2])), \
                              reverse=Reverse)
    else:
      self.node_list = sorted(children_list, key=lambda Node: Node.name(), reverse=Reverse)
    self.emit(SIGNAL("layoutChanged()"))

  def translation(self):
    self.nameTr = self.tr('Name')
    self.sizeTr = self.tr('Size')
    self.ATimeTr = self.tr('Accessed time')
    self.CTimeTr = self.tr('Changed time')
    self.MTimeTr = self.tr('Modified time')
    self.moduleTr = self.tr('Module')

