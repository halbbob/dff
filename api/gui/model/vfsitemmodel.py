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

from PyQt4.QtCore import SIGNAL, QAbstractItemModel, QModelIndex, QVariant, Qt, QDateTime, QSize, QThread, QMutex, QSemaphore
from PyQt4.QtGui import QColor, QIcon, QImage, QImageReader, QPixmap, QPixmapCache
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
      except VFSError:
        buff = ""
    if not len(buff):
      f = node.open()
      buff = f.read()
      f.close()
      load = img.loadFromData(buff)
    if load:
      img = img.scaled(QSize(128, 128), Qt.KeepAspectRatio, Qt.FastTransformation)
      return img
    return None

  def getThumb(self, node):
     buff = ""
     if node.size() > 6:
       file = node.open()
       head = file.find("\xff\xd8\xff", 3, "", 3)
       if head > 0 and head < node.size():
         foot = file.find("\xff\xd9", 2, "", long(head))
         if foot > 0 and foot < node.size():
           file.seek(head)
           buff = file.read(foot + 2 - head)
       file.close()
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

class VFSItemModel(QAbstractItemModel):
  #numberPopulated = QtCore.pyqtSignal(int)
  def __init__(self, __parent = None, event=False, fm = False):
    pass
    QAbstractItemModel.__init__(self, __parent)
    self.__parent = __parent
    self.VFS = libvfs.VFS.Get()
    self.map = {}
    self.imagesthumbnails = None
    self.connect(self, SIGNAL("dataImage"), self.setDataImage)
    #self.connect(self, SIGNAL("dataType"), self.setDataType)
    #self.connect(self, SIGNAL("refresh"), self.layoutChanged)
    self.fetchedItems = 0
    self.thumbQueued = {}
    self.fm = fm
    self.fm = False
    self.checkedNodes = set()
    if self.fm == True:
	setattr(self, "canFetchMore", self.scanFetchMore)
        setattr(self, "fetchMore", self.sfetchMore)
  #def modelRefresh(self):
  #  self.emit(SIGNAL("layoutChanged()"))

  #def setDataType(self, index, node, type = None):
     #self.__parent.currentView().viewport().update()
     #self.__parent.emit(SIGNAL("dataChanged(QModelIndex,QModelIndex)"), index, index)

  def setDataImage(self, index, node, image):
     pixmap = QPixmap().fromImage(image)
     pixmapCache.insert(str(node.this), pixmap)
     self.__parent.currentView().viewport().update()
     #self.emit(SIGNAL("dataChanged(QModelIndex,QModelIndex)"), index, index) fait segfault ...

  def imagesThumbnails(self):
     return self.imagesthumbnails

  #def setRootPath(self, node, item):
    #self.emit(SIGNAL("rootPathChanged()"), item)
    #self.rootItem = node
    #self.rootChildCount = node.childCount()
    ##typeWorker.clearQueue()
    #self.fetchedItems = 0
    #self.reset()

  def setRootPath(self, node, kompleter = None):
    self.rootItem = node
    self.rootChildCount = node.childCount()
    self.fetchedItems = 0
    typeWorker.clear()  #find a way to clear the queue / must have a queue by browser
    if kompleter == None:
      self.emit(SIGNAL("rootPathChanged"), node)

    self.reset()
 
  def scanFetchMore(self, parent):
    print "can fetch more"
    if not parent.isValid():
	parentItem = self.rootItem
    else:
         parentItem = self.VFS.getNodeFromPointer(parent.internalId())
    if self.fetchedItems < parentItem.childCount():
        #print "can fetchmore"
        return True
    #print "can't fetchmore"
    return False

  def qMin(self, x, y):
    if x < y:
      return x
    else:
      return y

  def sfetchMore(self, parent):
     print "fetch moore"
     if not parent.isValid():
        #print "get rooot"
	parentItem = self.rootItem
     else:
        #print "get node vrom pointer"
        parentItem = self.VFS.getNodeFromPointer(parent.internalId())
     #print parent
     remainder = parentItem.childCount() - self.fetchedItems
     itemsToFetch = self.qMin(50, remainder)
     #print "item fetched" + str(self.fetchedItems)
     #print "item to fetch " + str(itemsToFetch)
     self.beginInsertRows(QModelIndex(), self.fetchedItems, self.fetchedItems + itemsToFetch - 1)
     self.fetchedItems += itemsToFetch
     self.endInsertRows()
     self.numberPopulated.emit(itemsToFetch)

  def rowCount(self, parent):
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
    #print "getting data"
    if not index.isValid():
      return QVariant()
#XXX
    if self.fm == True:
      print "data fetch"
      if index.row() > self.rootItem.childCount() or index.row() < 0:
	 return QVariant()
    node = self.VFS.getNodeFromPointer(index.internalId())
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
    #if role == Qt.BackgroundRole: #XXX color pour bookmark
      ##if column == 0:
        ##if node.isDeleted():
          #return  QVariant(QColor(Qt.blue))
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
            elif typeWorker.isImage(mtype): #c koi le pluys spped isImage ou pixmap cache find ?
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
     #print "getting index"
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
     #print "getting parent"
     if not index.isValid():
       return QModelIndex()
     childItem = self.VFS.getNodeFromPointer(index.internalId())
     parentItem = childItem.parent()
     if parentItem.this == self.rootItem.this:
       return QModelIndex()
     n = 0
     children = parentItem.parent().children()
     #for node in children:
        #if parentItem.this == node.this:
	  #break
	#n += 1
     #print n
     #index = self.createIndex(n , 0, long(parentItem.this))
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
       if column == HNAME: 	#gere le trisate ici	
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
         #self.emit(SIGNAL("dataChanged(QModelIndex,QModelIndex)"), index, index)
	#XXX attention buggy bugger en vue thumbnails et refresh pas la vue tree 
     #^^^ utiliser pour le refresh du contenue des icons ? au lieu de refresh tous le model pour le thumbnails ? 
     return True #return true if ok 	

  def flags(self, flag):
     return (Qt.ItemIsSelectable | Qt.ItemIsUserCheckable | Qt.ItemIsTristate | Qt.ItemIsEnabled )  


class VfsSearchItemModel(QAbstractItemModel):
  #numberPopulated = QtCore.pyqtSignal(int)
  def __init__(self, node_list, __parent = None, event=False, fm = False):
    self.__node_list = node_list

  def data(self, index, role):
    if not index.isValid():
      return QVariant()
    if index.row() >= self.__node_list.size():
      return QVariant()
    return QVariant()

  def columnCount(self, parent = QModelIndex()):
     return 6

  def rowCount(self, parent = QModelIndex()):
     return self.__node_list.count()

  def index(self, row, column, parent = QModelIndex()):
     return index

  def parent(self, index):
     return index

