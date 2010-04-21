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

from PyQt4.QtCore import SIGNAL, QAbstractItemModel, QModelIndex, QVariant, Qt, QDateTime, QSize
from PyQt4.QtGui import QColor, QIcon, QImage, QImageReader, QPixmap, QPixmapCache

import re
from api.magic.filetype import *
from api.vfs import libvfs

HNAME = 0
HSIZE = 1
HACCESSED = 2 
HCHANGED = 3
HMODIFIED = 4
HMODULE = 5


class VFSItemModel(QAbstractItemModel):
  def __init__(self, parent = None):
    QAbstractItemModel.__init__(self, parent)	
    self.VFS = libvfs.VFS.Get()
    self.map = {}
    self.thumbnails = None
    self.VFS.set_callback("refresh_tree", self.refresh)
  
  def refresh(self, node):
    self.emit(SIGNAL("layoutChanged()")) 

  def setThumbnails(self, flag):
     self.thumbnails = flag
     if flag:
      self.reg_viewer = re.compile("(JPEG|JPG|jpg|jpeg|GIF|gif|bmp|BMP|png|PNG|pbm|PBM|pgm|PGM|ppm|PPM|xpm|XPM|xbm|XBM).*", re.IGNORECASE)
      self.ft = FILETYPE()

  def setDirPath(self, node):
    self.__map = {} #? 
    self.rootItem = node
    self.reset()  
 
  #def canFetchMore(self, index):
    #if self.fm[index] < index.internalPointer().next.size():
      #return True
    #else:
      #return False

  #def qMin(self, x, y):
    #if x < y:
      #return x
    #else:
      #return y
    #return x

  #def fetchMore(self, index):
    #remainder = index.internalPointer().next.size() - self.fm[index]
    #itemsToFetch = self.qMin(100, remainder)
    
    #self.beginInsertRows(QModelIndex(), self.fm[index], self.fm[index] + itemsToFetch)
    #self.fm[index] += itemsToFetch
    
    #self.endInsertRows()
    #self.emit(SIGNAL("numberPopulated"), itemsToFetch)
      
  def rowCount(self, parent):
    if not parent.isValid():
	parentItem = self.rootItem
    else:
        parentItem = parent.internalPointer()
    return len(parentItem.next)	

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
    node = index.internalPointer()
    column = index.column()
    if role == Qt.DisplayRole :
      if column == HNAME:
        return QVariant(node.name)
      if column == HSIZE:
        return QVariant(node.attr.size)
      time = node.attr.time
      try :
        if column == HACCESSED:
          return QVariant(QDateTime(time['accessed'].get_time()))
        if column == HCHANGED:
          return QVariant(QDateTime(time['changed'].get_time()))
        if column == HMODIFIED:
          return QVariant(QDateTime(time['modified'].get_time()))
      except IndexError:
	pass
      if column == HMODULE:
        return QVariant(node.fsobj.name)
    if role == Qt.TextColorRole:
      if column == 0:
        if node.attr.deleted:
          return  QVariant(QColor(Qt.red))
    if role == Qt.DecorationRole:
      if column == HNAME:
        if node.next.empty():
          if self.thumbnails:
            icon = self.createThumbnails(node)
            if icon:
              return QVariant(QIcon(icon))
          return QVariant(QIcon(":folder_empty_128.png"))
        else:
          if node.attr.size != 0: 
            return QVariant(QIcon(":folder_documents_128.png"))
          else:
	    return QVariant(QIcon(":folder_128.png"))
    return QVariant() 

  def getThumb(self, node):
     buff = ""
     if node.attr.size > 6:
       file = node.open()
       head = file.find("\xff\xd8\xff", 3, "", 3)
       if head > 0 and head < node.attr.size:
         foot = file.find("\xff\xd9", 2, "", int(head))
         if foot > 0 and foot < node.attr.size:
           file.seek(head)
           buff = file.read(foot + 2 - head)
       file.close()
     return buff

  def createThumbnails(self, node):
     if node.attr.size != 0: 
       map = node.attr.smap
       try:
         ftype = node.attr.smap["type"] 
       except IndexError:
         self.ft.filetype(node)
         ftype = node.attr.smap["type"]
       res = self.reg_viewer.match(ftype)
       if res != None:
         type = ftype[:ftype.find(" ")]
         buff = ""
         tags = None
         if type in ["JPEG", "JPG", "jpg", "JPEG"]:
           try:
              buff = self.getThumb(node)
           except:
              buff = ""
         if len(buff) == 0:
           f = node.open()
           f.seek(0, 0)
           buff = f.read()
           f.close()
         img = QImage()
         if img.loadFromData(buff, type):
           img = img.scaled(QSize(128, 128), Qt.KeepAspectRatio, Qt.FastTransformation)
           pixmap = QPixmap()
           pixmap = pixmap.fromImage(img) 
           return pixmap
       return None  
 
  def columnCount(self, parent = QModelIndex()):
     return 6 

  def index(self, row, column, parent = QModelIndex()):
     if not self.hasIndex(row, column, parent):
       return QModelIndex()

     if parent.isValid():
       parentItem = parent.internalPointer()
     else:
       parentItem = self.rootItem 
     childItem = parentItem.next[row]

     try :
       childItem, row = self.map[childItem.absolute()]
     except KeyError:
       self.map[childItem.absolute()] = (childItem, row)

     index = self.createIndex(row, column, childItem)
     return index

  def parent(self, index):
     if not index.isValid(): 
       return QModelIndex()
     childItem = index.internalPointer()
     parentItem = childItem.parent
     
     if parentItem.absolute() == self.rootItem.absolute():
       return QModelIndex()

     parentItem, n = self.map[parentItem.absolute()]
     index = self.createIndex(n , 0, parentItem)
     return index

  def hasChildren(self, parent):
    if not parent.isValid():
	self.parentItem = self.rootItem
	return not self.rootItem.empty_child()
    else:
        self.parentItem = parent.internalPointer()
  	return not self.parentItem.empty_child()

