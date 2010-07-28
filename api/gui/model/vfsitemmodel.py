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

from PyQt4.QtCore import SIGNAL, QAbstractItemModel, QModelIndex, QVariant, Qt, QDateTime, QSize, QThread
from PyQt4.QtGui import QColor, QIcon, QImage, QImageReader, QPixmap, QPixmapCache

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
    if type in ["JPEG", "JPG", "jpg", "JPEG"]:
      try:
        buff = self.getThumb(node)
        load = img.loadFromData(buff, type)
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
         foot = file.find("\xff\xd9", 2, "", int(head))
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

  def enqueue(self, parent, index, node):
    self.typeQueue.put((parent, index, node))

  def clearQueue(self):
     self.typeQueue = Queue() # ok ?
     #self.typeQueue.all_tasks_done()
     #print self.typeQueue.empty()
     pass

  def isImage(self, ftype):
      #return  self.regImage.match(type)
    res = self.regImage.search(ftype)
    return res

  def run(self):
     count = 0
     while True:
       (parent, index, node) = self.typeQueue.get()
       if node.size():
         self.ft.filetype(node)
         attrs = node.staticAttributes()
         map = attrs.attributes()
         ftype = str(map["type"])
         if parent.imagesthumbnails and self.isImage(ftype):
           type = ftype[:ftype.find(" ")]
           thumb = ImageThumb()
           img = thumb.getImage(type, node, index)
           if img:
             parent.emit(SIGNAL('dataImage'), index, node, img)
           else:
             val = Variant("broken")
             val.thisown = False
             node.setStaticAttribute("type", val)
             #parent.emit(SIGNAL('dataType'), index, node) 
       self.typeQueue.task_done()

typeWorker = TypeWorker()
typeWorker.start()

class VFSItemModel(QAbstractItemModel):
  def __init__(self, __parent = None, event=False):
    QAbstractItemModel.__init__(self, __parent)
    self.__parent = __parent
    self.VFS = libvfs.VFS.Get()
    self.map = {}
    self.imagesthumbnails = None
    self.connect(self, SIGNAL("dataImage"), self.setDataImage)
    self.connect(self, SIGNAL("dataType"), self.setDataType)
    #self.connect(self, SIGNAL("refresh"), self.layoutChanged)
    self.fetchedItems = 0
    self.thumbQueued = {}

  #def modelRefresh(self):
  #  self.emit(SIGNAL("layoutChanged()")) 

  def setDataType(self, index, node, type = None):
     self.__parent.currentView().viewport().update()

  def setDataImage(self, index, node, image):
     pixmap = QPixmap().fromImage(image)
     pixmapCache.insert(str(node.this), pixmap)
     self.__parent.currentView().viewport().update()

  def imagesThumbnails(self):
     return self.imagesthumbnails

  def setRootPath(self, node, item):
    self.emit(SIGNAL("rootPathChanged()"), item)
    self.rootItem = node
    self.rootChildCount = node.childCount()
    #typeWorker.clearQueue()
    #self.fetchedItems = 0
    self.reset()  

  def setRootPath(self, node):
    self.rootItem = node
    self.rootChildCount = node.childCount()
    #self.fetchedItems = 0
    #typeWorker.clearQueue()  #find a way to clear the queue / must have a queue by browser
    self.reset()  
# 
  #def canFetchMore(self, parent):
    #if self.fetchedItems < self.rootChildCount:
        #print "can fetchmore"
        #return True
    #print "can't fetchmore"
    #return False
#
  #def qMin(self, x, y):
    #if x < y:
      #return x
    #else:
      #return y
#
  #def fetchMore(self, parent):
     #print parent
     #remainder = self.rootChildCount - self.fetchedItems
     #itemsToFetch = self.qMin(100, remainder)
     #print "item fetched" + str(self.fetchedItems)
     #print "item to fetch " + str(itemsToFetch)
     #self.beginInsertRows(QModelIndex(), self.fetchedItems, self.fetchedItems + itemsToFetch)
     #self.fetchedItems += itemsToFetch
     #self.endInsertRows()
     #self.numberPopulated(itemsToFetch)
      
  def rowCount(self, parent):
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
        return QVariant('Name')
      if section == HSIZE:
        return QVariant('Size')
      if section == HACCESSED:
        return QVariant('Accessed time')
      if section == HCHANGED:
        return QVariant('Changed time')
      if section == HMODIFIED:
        return QVariant('Modified time')
      if section == HMODULE:
        return QVariant('Module')

  def data(self, index, role):
    if not index.isValid():
      return QVariant()
    node = self.VFS.getNodeFromPointer(index.internalId())
    column = index.column()
    if role == Qt.DisplayRole :
      if column == HNAME:
        return QVariant(node.name())
      if column == HSIZE:
        return QVariant(node.size())
      try :
        time = node.times()
        if column == HACCESSED:
          accessed = time['accessed']
          if accessed != None:
            return QVariant(QDateTime(accessed.get_time()))
          else:
            return QVariant()
        if column == HCHANGED:
          changed = time['changed']
          if changed != None:
            return QVariant(QDateTime(changed.get_time()))
          else:
            return QVariant()
        if column == HMODIFIED:
          modified = time['modified']
          if modified != None:
            return QVariant(QDateTime(modified.get_time()))
          else:
            return QVariant()
      except IndexError:
        pass 
      if column == HMODULE:
        fsobj = node.fsobj()
        if (fsobj != None):
          return QVariant(fsobj.name)
        else:
          return QVariant()
    if role == Qt.TextColorRole:
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
              ftype = str(map["type"])
            except (IndexError, AttributeError):
              typeWorker.enqueue(self, index, node)
              return QVariant(QIcon(":file_temporary.png"))
            if ftype == "broken":
              return QVariant(QIcon(":file_broken.png"))
            #transparent broken icon (too slow !)	
            #pixmap = QPixmap(":image.png")
            #broken = QPixmap(":file_broken.png")
            #mask = broken.createHeuristicMask()  
            #pixmap.setMask(mask)
            #return QVariant(QIcon(pixmap))
            #return QVariant(QIcon(":file_broken.png")) 
            pixmap = pixmapCache.find(str(node.this))
            if pixmap:
              return QVariant(QIcon(pixmap))
            elif typeWorker.isImage(ftype):
              typeWorker.enqueue(self, index, node)
              return QVariant(QIcon(":file_temporary.png"))
          return QVariant(QIcon(":folder_empty_128.png"))
        else:
          if node.size() != 0:
	    return QVariant(QIcon(":folder_documents_128.png"))
          else:
	    return QVariant(QIcon(":folder_128.png"))
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
     childItem = parentItem.children()[row]
     index = self.createIndex(row, column, int(childItem.this))
     return index

  def parent(self, index):
     if not index.isValid(): 
       return QModelIndex()
     childItem = self.VFS.getNodeFromPointer(index.internalId())
     parentItem = childItem.parent()
     if parentItem.this == self.rootItem.this:
       return QModelIndex()
     n = 0
     children = parentItem.parent().children()
     for node in children:
        if parentItem.this == node.this:
	  break
	n += 1
     index = self.createIndex(n , 0, int(parentItem.this))
     return index

  def hasChildren(self, parent):
    if not parent.isValid():
	self.parentItem = self.rootItem
        return self.rootItem.hasChildren()
    else:
        self.parentItem = self.VFS.getNodeFromPointer(parent.internalId())
        return self.parentItem.hasChildren()
