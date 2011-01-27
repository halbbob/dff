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

from PyQt4.QtCore import Qt, QString, QEvent
from PyQt4.QtGui import QTreeWidget, QTreeWidgetItem#, QHeaderView 
from api.vfs.libvfs import Attributes
from api.magic.filetype import FILETYPE

from ui.gui.resources.ui_propertytable import Ui_PropertyTable

class PropertyTable(QTreeWidget, Ui_PropertyTable):
  def __init__(self, parent):
    QTreeWidget.__init__(self)
    self.setupUi(self)
    self.node = None

# Hide labels used for translators
    self.itemName.setVisible(False)
    self.itemType.setVisible(False)
    self.itemFolder.setVisible(False)
    self.itemFile.setVisible(False)
    self.itemModApplied.setVisible(False)
    self.itemEmpty.setVisible(False)
    self.itemDeleted.setVisible(False)
    self.itemGeneratedBy.setVisible(False)
    self.itemSize.setVisible(False)
    self.itemRelevantMod.setVisible(False)
    self.itemChildren.setVisible(False)
    self.itemFiles.setVisible(False)
    self.itemTotal.setVisible(False)
    self.itemBytes.setVisible(False)
    self.itemFolders.setVisible(False)
    self.itemTimes.setVisible(False)
    self.itemExtAttr.setVisible(False)
    self.itemStaAttr.setVisible(False)
    
    self.ft = FILETYPE()


  def fillBase(self, node):
    fsobj = node.fsobj()
    fsobjname = ""
    if fsobj != None:
      fsobjname = fsobj.name
    itemName = QTreeWidgetItem(self)
    itemName.setText(0, self.itemName.text())
    itemName.setText(1, str(node.name()))

    itemName = QTreeWidgetItem(self)
    itemName.setText(0, self.itemType.text())
    typestr = ""
    if node.isFile():
      typestr += self.itemFile.text()
      if node.hasChildren():
        typestr += self.itemModApplied.text()
        self.fillChildren(node)
      self.fillCompatModule(node)
        
    if node.isDir():
      typestr += self.itemFolder.text()
      if not node.hasChildren():
        typestr += self.itemEmpty.text()
    if node.isDeleted():
      typestr += self.itemDeleted.text()
    itemName.setText(1, typestr)

    itemModule = QTreeWidgetItem(self)
    itemModule.setText(0, self.itemGeneratedBy.text())
    itemModule.setText(1, str(fsobjname))
    
    itemSize = QTreeWidgetItem(self)
    itemSize.setText(0, self.itemSize.text())
    itemSize.setText(1, str(node.size()))


  def fillCompatModule(self, node):
    l = self.ft.findcompattype(node)
    if len(l) > 0:
      itemCompat = QTreeWidgetItem(self)
      itemCompat.setText(0, self.itemRelevantMod.text())
      buff = ""
      for i in l:
        buff += str(i) + " " 
      itemCompat.setText(1, buff)

  def fillChildren(self, node):
    itemChildren = QTreeWidgetItem(self)
    itemChildren.setText(0, self.itemChildren.text())
    itemChildren.setText(1, str(node.childCount()))
    children = node.children()
    filessize = 0
    filecount = 0
    dircount = 0
    for child in children:
      if child.isFile():
        filessize += child.size()
        filecount += 1
      elif child.isDir():
        dircount += 1
    if filecount > 0:
      itemFile = QTreeWidgetItem(itemChildren)
      itemFile.setText(0, self.itemFiles.text())
      itemFile.setText(1, str(filecount) + self.itemTot.text() + str(filessize) + self.itemBytes())
    if dircount > 0:
      itemFolder = QTreeWidgetItem(itemChildren)
      itemFolder.setText(0, self.itemFolders.text())
      itemFolder.setText(1, str(dircount))
    self.expandItem(itemChildren)    
    

  def fillTimes(self, node):
      try:
        ntimes = node.times()
        itemTimes = QTreeWidgetItem(self)
        itemTimes.setText(0, self.itemTimes.text())
        for timetype, t in ntimes.iteritems():
          itemTime = QTreeWidgetItem(itemTimes)
          itemTime.setText(0, str(timetype))
          itemTime.setText(1, str(t.get_time()))
        self.expandItem(itemTimes)
      except IndexError, AttributeError:
        pass


  def fillExtendedAttributes(self, node):
    attrs = Attributes()
    attrs.thisown = False
    node.extendedAttributes(attrs)
    map = attrs.attributes()
    if len(map) > 0:
      itemExtendedAttr = QTreeWidgetItem(self)
      itemExtendedAttr.setText(0, self.itemExtAttr.text())
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

  
  def fillStaticAttributes(self, node):
    try:
      attrs = node.staticAttributes()
      map = attrs.attributes()
      itemStaticAttr = QTreeWidgetItem(self)
      itemStaticAttr.setText(0, self.itemStaAttr.text())
      for key, value in map.iteritems():
        item = QTreeWidgetItem(itemStaticAttr)
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
      self.expandItem(itemStaticAttr)
    except (IndexError, AttributeError):
      pass


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


  def fill(self, node = None):
    if not node:
      node = self.node
    self.node = node
    self.clear()
    if self.isVisible():
      self.fillBase(node)
      self.fillTimes(node)
      self.fillStaticAttributes(node)
      self.fillExtendedAttributes(node)


  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.retranslateUi(self)
      if self.node is not None:
        self.fill()

    else:
      QTreeWidget.changeEvent(self, event)


