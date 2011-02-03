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
from api.magic.filetype import *
from api.vfs import libvfs, iodevice
from api.variant.libvariant import Variant

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
    if type == "image/jpeg":
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
    self.ft = FILETYPE()
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
         self.ft.filetype(node) #ret plustrapide?
         attrs = node.staticAttributes()
         map = attrs.attributes()
         ftype = str(map["mime-type"])
         if parent.imagesthumbnails and self.isImage(ftype):
           thumb = ImageThumb()
           img = thumb.getImage(ftype, node, index)
           if img:
             parent.emit(SIGNAL('dataImage'), index, node, img)
           else:
             val = Variant("broken " + str(ftype))
             val.thisown = False
             node.setStaticAttribute("mime-type", val)

typeWorker = TypeWorker()
typeWorker.start()

class TreeModel(QAbstractItemModel):
  def __init__(self, __parent = None, event=False, fm = False):
    QAbstractItemModel.__init__(self, __parent)
    self.__parent = __parent
    self.VFS = libvfs.VFS.Get()
    self.map = {}
    self.imagesthumbnails = None
    self.connect(self, SIGNAL("dataImage"), self.setDataImage)
    self.fetchedItems = 0
    self.thumbQueued = {}
    self.checkedNodes = set()

  def setDataImage(self, index, node, image):
     pixmap = QPixmap().fromImage(image)
     pixmapCache.insert(str(node.this), pixmap)
     self.__parent.currentView().viewport().update()

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

class VFSItemModel(QAbstractItemModel):
  numberPopulated = QtCore.pyqtSignal(int)
  def __init__(self, __parent = None, event=False, fm = False):
    QAbstractItemModel.__init__(self, __parent)
    self.__parent = __parent
    self.VFS = libvfs.VFS.Get()
    self.map = {}

    self.imagesthumbnails = None
    self.connect(self, SIGNAL("dataImage"), self.setDataImage)
    self.fetchedItems = 0
    self.thumbQueued = {}
    self.fm = fm
    self.fm = False
    self.checkedNodes = set()
    self.node_list = []
    setattr(self, "canFetchMore", self.canFetchMore)
    setattr(self, "fetchMore", self.fetchMore)

  def setDataImage(self, index, node, image):
     pixmap = QPixmap().fromImage(image)
     pixmapCache.insert(str(node.this), pixmap)
     self.__parent.currentView().viewport().update()

  def imagesThumbnails(self):
     return self.imagesthumbnails

  def setRootPath(self, node, kompleter = None):
    self.fetchedItems = 0
    typeWorker.clear()
    self.rootItem = node
    del self.node_list[:]
    self.sort(HNAME, Qt.AscendingOrder)
    if kompleter == None:
      self.emit(SIGNAL("rootPathChanged"), node)
    self.reset()

  def canFetchMore(self, parent):
    if self.fetchedItems < len(self.node_list):
      return True
    return False

  def fetchMore(self, parent):
     remainder = len(self.node_list) - self.fetchedItems
     itemsToFetch = self.qMin(50, remainder)
     self.beginInsertRows(parent, self.fetchedItems, self.fetchedItems + itemsToFetch - 1)
     self.fetchedItems += itemsToFetch
     self.endInsertRows()

  def qMin(self, x, y):
    if x < y:
      return x
    else:
      return y

  def rowCount(self, parent):
    return self.fetchedItems
    if self.fm == True:
	return self.fetchedItems
    if not parent.isValid():
	parentItem = self.rootItem
    else:
        parentItem = self.VFS.getNodeFromPointer(parent.internalId())
    return parentItem.childCount()

  def headerData(self, section, orientation, role=Qt.DisplayRole):
    if role != Qt.DisplayRole:
      return QVariant()
    if orientation == Qt.Horizontal:
      if section == HNAME:
        return QVariant(self.tr('Name'))
      if section == HSIZE:
        return QVariant(self.tr('Size'))
      if section == HACCESSED:
        return QVariant(self.tr('Accessed time'))
      if section == HCHANGED:
        return QVariant(self.tr('Changed time'))
      if section == HMODIFIED:
        return QVariant(self.tr('Modified time'))
      if section == HMODULE:
        return QVariant(self.tr('Module'))

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
        if column == HACCESSED:
          time = node.times()
          accessed = time['accessed']
          if accessed != None:
            return QVariant(QDateTime(accessed.get_time()))
          else:
            return QVariant()
        if column == HCHANGED:
          time = node.times()
          changed = time['changed']
          if changed != None:
            return QVariant(QDateTime(changed.get_time()))
          else:
            return QVariant()
        if column == HMODIFIED:
          time = node.times()
          modified = time['modified']
          if modified != None:
            return QVariant(QDateTime(modified.get_time()))
          else:
            return QVariant()
      except IndexError:
        return QVariant()
      if column == HMODULE:
        fsobj = node.fsobj()
        if (fsobj != None):
          return QVariant(fsobj.name)
        else:
          return QVariant()
    if role == Qt.ForegroundRole:
      if column == 0:
        if node.isDeleted():
          return  QVariant(QColor(Qt.red))
    if role == Qt.DecorationRole:
      if column == HNAME:
        if not node.hasChildren():
          if node.isDir():
            return QVariant(QIcon(":folder_128.png"))
          if not node.size():
            return QVariant(QIcon(":folder_empty_128.png"))
          if self.imagesthumbnails:
            try:
              attrs = node.staticAttributes()
              map = attrs.attributes()
              mtype = str(map["mime-type"])
            except (IndexError, AttributeError):
              typeWorker.enqueue(self, index, node)
              return QVariant(QIcon(":file_temporary.png"))
            if mtype[0:6] == "broken":
              return QVariant(QIcon(":file_broken.png"))
            pixmap = pixmapCache.find(str(node.this))
            if pixmap:
                return QVariant(QIcon(pixmap))
            elif typeWorker.isImage(mtype):
              typeWorker.enqueue(self, index, node)
              return QVariant(QIcon(":file_temporary.png"))
          return QVariant(QIcon(":folder_empty_128.png"))
        else:
          if node.size() != 0:
	    return QVariant(QIcon(":folder_documents_128.png"))
          else:
	    return QVariant(QIcon(":folder_128.png"))
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
     return 6

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
     return True

  def flags(self, flag):
     return (Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsTristate | Qt.ItemIsEnabled )  

  def sort(self, column, order):
    """
    Overload of the sort method.
    """
    self.emit(SIGNAL("layoutAboutToBeChanged()"))
    parentItem = self.rootItem
    if parentItem == None:
      self.emit(SIGNAL("layoutChanged()"))
      return
    children_list = parentItem.children()
    if order == Qt.DescendingOrder:
      Reverse = True
    else:
      Reverse = False
    if column == HNAME:
      self.node_list = sorted(children_list, key=lambda Node: Node.name(), reverse=Reverse)
    elif column == HSIZE:
      self.node_list = sorted(children_list, key=lambda Node: Node.size(), reverse=Reverse)
    elif column == HACCESSED:
      self.node_list = sorted(children_list, key=lambda Node: Node.times()["accessed"], reverse=Reverse)
    elif column == HCHANGED:
      self.node_list = sorted(children_list, key=lambda Node: Node.times()["changed"], reverse=Reverse)
    elif column == HMODIFIED:
      self.node_list = sorted(children_list, key=lambda Node: Node.times()["modified"], reverse=Reverse)
    elif column == HMODULE:
      self.node_list = sorted(children_list, key=lambda Node: Node.fsobj(), reverse=Reverse)
    else:
      self.node_list = sorted(children_list, key=lambda Node: Node.name(), reverse=Reverse)
    self.emit(SIGNAL("layoutChanged()"))
