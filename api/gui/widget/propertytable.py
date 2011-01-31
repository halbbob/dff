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
#  Solal Jacob <solal.jacob@digital-forensic.org>
#

from PyQt4.QtCore import Qt, QString
from PyQt4.QtGui import QTreeWidget, QTreeWidgetItem#, QHeaderView 
#from api.vfs.libvfs import Attributes

class PropertyTable(QTreeWidget):
  def __init__(self, parent):
    QTreeWidget.__init__(self)
    self.setColumnCount(2)
    self.setHeaderLabels([self.tr("Attribute"), self.tr("Value")])
    self.setAlternatingRowColors(True)

  def fillBase(self, node):
    fsobj = node.fsobj()
    fsobjname = ""
    if fsobj != None:
      fsobjname = fsobj.name
    itemName = QTreeWidgetItem(self)
    itemName.setText(0, self.tr("name"))
    itemName.setText(1, str(node.name()))

    itemName = QTreeWidgetItem(self)
    itemName.setText(0, self.tr("node type"))
    typestr = ""
    if node.isFile():
      typestr += self.tr("file")
      if node.hasChildren():
        typestr += " " + self.tr("with module(s) applied on it")
      self.fillCompatModule(node)
    if node.hasChildren():
      self.fillChildren(node)
        
    if node.isDir():
      typestr += self.tr("folder")
      if not node.hasChildren():
        typestr += " " + self.tr("empty")
    if node.isDeleted():
      typestr += " " + self.tr("deleted")
    itemName.setText(1, typestr)

    itemModule = QTreeWidgetItem(self)
    itemModule.setText(0, self.tr("generated by"))
    itemModule.setText(1, str(fsobjname))
    
    itemSize = QTreeWidgetItem(self)
    itemSize.setText(0, self.tr("size"))
    itemSize.setText(1, str(node.size()))


  def fillCompatModule(self, node):
    l = node.compatibleModules()
    if len(l) > 0:
      itemCompat = QTreeWidgetItem(self)
      itemCompat.setText(0, self.tr("relevant module(s)"))
      buff = ""
      for i in l:
        buff += str(i) + " " 
      itemCompat.setText(1, buff)

  def fillChildren(self, node): 
    itemChildren = QTreeWidgetItem(self)
    itemChildren.setText(0, "children")
    itemChildren.setText(1, str(node.childCount()))
    children = node.children()
    filessize = 0
    filecount = 0
    dircount = 0
    for child in children:
      if child.size():
        filessize += child.size()
        filecount += 1
      elif child.isDir() or child.hasChildren():
        dircount += 1
    if filecount > 0:
      itemFile = QTreeWidgetItem(itemChildren)
      itemFile.setText(0, "file(s)")
      itemFile.setText(1, str(filecount) + " totalizing " + str(filessize) + " bytes")
    if dircount > 0:
      itemFolder = QTreeWidgetItem(itemChildren)
      itemFolder.setText(0, "folder(s)")
      itemFolder.setText(1, str(dircount))
    self.expandItem(itemChildren)    
    
  def fillAttributes(self, node):
    map = node.attributes()
    map.thisown = False
    if len(map) > 0:
      itemExtendedAttr = QTreeWidgetItem(self)
      itemExtendedAttr.setText(0, self.tr("attributes"))
      for key, value in map.iteritems():
        item = QTreeWidgetItem(itemExtendedAttr)
        item.setText(0, str(key))
        if str(type(value)).find("Variant") != -1:
          if str(type(value.value())).find("VMap") != -1:
            self.fillMap(item, value.value())
          elif str(type(value.value())).find("VList") != -1:
            self.fillList(item, value.value())
          elif str(value).find("vtime") != -1:
            item.setText(1, str(value.value().get_time()))
          else:
            item.setText(1, str(value))
        else:
          if str(value).find("vtime") != -1:
            item.setText(1, str(value.value().get_time()))
          else:
            item.setText(1, str(value))
      self.expandItem(itemExtendedAttr)

  def fillMap(self, parent, map):
    for key, value in map.iteritems():
      item = QTreeWidgetItem(parent)
      item.setText(0, str(key))
      if str(type(value)).find("Variant") != -1:
        if str(type(value.value())).find("VMap") != -1:
          self.fillMap(item, value.value())
        elif str(type(value.value())).find("VList") != -1:
          self.fillList(item, value.value())
        elif str(value).find("vtime") != -1:
          item.setText(1, str(value.value().get_time()))
        else:
          item.setText(1, str(value))
      else:
        if str(value).find("vtime") != -1:
          item.setText(1, str(value.value().get_time()))
        else:
          item.setText(1, str(value))
        

  def fillList(self, parent, list):
    for i in list:
      item = QTreeWidgetItem(parent)
      if str(i).find("vtime") != -1:
        item.setText(1, str(i.value().get_time()))
      else:
        item.setText(1, str(i))


  def fill(self, node):
    self.clear()
    if self.isVisible():
      self.fillBase(node)
      self.fillAttributes(node)
