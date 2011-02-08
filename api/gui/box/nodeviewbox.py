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
#  Jeremy Mounier <jmo@digital-forensic.org> 

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *

#from api.gui.widget.nodefilterbox import NodeFilterBox

from api.gui.model.vfsitemmodel import  VFSItemModel
from api.gui.widget.propertytable import PropertyTable
from api.vfs.vfs import vfs, Node, DEvent, VLink
from api.vfs import libvfs
from api.variant.libvariant import typeId
from ui.gui.resources.ui_nodeviewbox import Ui_NodeViewBox
from ui.gui.resources.ui_bookmarkdialog import Ui_AddBookmark
from ui.gui.resources.ui_selectattrs import Ui_SelectAttr

class NodeViewBox(QWidget, Ui_NodeViewBox):
  def __init__(self, parent):
    QWidget.__init__(self)
    self.setupUi(self)
    self.vfs = vfs()
    self.VFS = libvfs.VFS.Get()
    self.parent = parent
    self.button = {}
 
    self.history = []
    self.history.append("/")
    self.currentPathId = -1

    self.bookmarkCategories = []
    self.bookmarkNode = self.vfs.getnode('/Bookmarks/')

    self.addPropertyTable()

    self.parent.connect(self.previous, SIGNAL("clicked()"), self.moveToPrevious)
    self.setPrevDropButton()
    self.parent.connect(self.next, SIGNAL("clicked()"), self.moveToNext)
    self.setNextDropButton()
    self.parent.connect(self.top, SIGNAL("clicked()"), self.moveToTop)
    self.parent.connect(self.root, SIGNAL("clicked()"), self.goHome)
    
    self.createPathEdit()
    self.connect(self.viewbox, SIGNAL("activated(int)"), self.viewboxChanged)

    self.createCheckBoxAttribute()
    self.connect(self.addToBookmark, SIGNAL("clicked()"), self.bookmark)
    self.connect(self.search, SIGNAL("clicked()"), self.searchActivated)
    self.connect(self.imagethumb, SIGNAL("clicked()"), self.imagethumbActivated)

    self.connect(self.attrSelect, SIGNAL("clicked()"), self.attrSelectView)

    self.parent.connect(self.thumbSize, SIGNAL("currentIndexChanged(QString)"), self.parent.sizeChanged)
    
    self.tableActivated()

  def viewboxChanged(self, index):
    if index == 0:
      self.tableActivated()
    elif index == 1:
      self.thumbActivated()
    elif index == 2:
      self.leftTreeActivated()

  def addPropertyTable(self):
    self.propertyTable = PropertyTable(self)
    self.propertyTable.setVisible(True)
    self.propertyTable.setMinimumSize(QSize(150, 300))
    self.parent.browserLayout.addWidget(self.propertyTable)

  def setPrevDropButton(self):
    self.prevdrop.setFixedSize(QSize(16, 16))
    self.prevmenu = QMenu()
    self.prevdrop.setMenu(self.prevmenu)
    self.connect(self.prevmenu, SIGNAL("triggered(QAction*)"), self.prevMenuTriggered)

  def setPrevMenu(self):
    self.prevmenu.clear()
    h = self.history[:self.currentPathId]
    for path in h:
      self.prevmenu.addAction(path)

  def prevMenuTriggered(self, action):
    self.parent.model.setRootPath(self.vfs.getnode(str(action.text())))

  def setNextDropButton(self):
    self.nextdrop.setFixedSize(QSize(16, 16))
    self.nextmenu = QMenu()
    self.nextdrop.setMenu(self.nextmenu)
    self.connect(self.nextmenu, SIGNAL("triggered(QAction*)"), self.nextMenuTriggered)

  def setNextMenu(self):
    self.nextmenu.clear()
    h = self.history[self.currentPathId+1:]
    for path in h:
      self.nextmenu.addAction(path)

  def pathInHistory(self, path, hlist):
    for p in hlist:
      if p == path:
        return True
    return False

  def nextMenuTriggered(self, action):
    self.parent.model.setRootPath(self.vfs.getnode(str(action.text())))


  def goHome(self):
     self.parent.model.setRootPath(self.vfs.getnode("/"))    

  def createCheckBoxAttribute(self):
    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.checkboxAttribute.setCheckState(True)
    else:
      self.checkboxAttribute.setChecked(True)
    self.checkboxAttribute.setEnabled(True)
    self.checkboxAttribute.setTristate(False)

    self.connect(self.checkboxAttribute, SIGNAL("stateChanged(int)"), self.checkboxAttributeChanged)

  def checkboxAttributeChanged(self, state):
    if state:
       self.propertyTable.setVisible(True)
    else:
        self.propertyTable.setVisible(False)	

  def moveToTop(self):
     parent =  self.parent.model.rootItem.parent()
     self.parent.model.setRootPath(parent)
     self.changeNavigationState()

  def moveToPrevious(self):
    if self.currentPathId > 0:
      self.currentPathId = self.currentPathId - 1
      path = self.history[self.currentPathId]
      node = self.vfs.getnode(path)
      self.parent.model.setRootPath(node, 1)
      self.changeNavigationState()
      self.pathedit.setCompleter(None)
      self.pathedit.clear()
      self.pathedit.insert(path[1:])
      self.pathedit.setCompleter(self.completer)

  def moveToNext(self):
    if self.currentPathId < len(self.history) - 1:
      self.currentPathId = self.currentPathId + 1
      path = self.history[self.currentPathId]
      node = self.vfs.getnode(path)
      self.parent.model.setRootPath(node, 1)
      self.changeNavigationState()
      self.pathedit.setCompleter(None)
      self.pathedit.clear()
      self.pathedit.insert(path[1:])
      self.pathedit.setCompleter(self.completer)
 
  def imagethumbActivated(self):
    if self.parent.model.imagesThumbnails():
      self.parent.model.setImagesThumbnails(False)
      self.parent.model.reset()
    else:
      self.parent.model.setImagesThumbnails(True)
      self.parent.model.reset()

 
  def leftTreeActivated(self):
     if self.parent.treeView.isVisible():
       self.parent.treeView.setVisible(False)
     else:
       self.parent.treeView.setVisible(True)
 
  def tableActivated(self):
     self.parent.tableView.setVisible(True)
     self.parent.thumbsView.setVisible(False)
     self.thumbSize.setEnabled(False)
  
  def thumbActivated(self):
     self.checkboxAttribute.setEnabled(True)
     if self.checkboxAttribute.isChecked():
       self.propertyTable.setVisible(True)
     else :
        self.propertyTable.setVisible(False)
     self.parent.tableView.setVisible(False)
     self.parent.thumbsView.setVisible(True)
     self.thumbSize.setEnabled(True)

  def searchActivated(self):
     if self.parent.nodeFilterBox.isVisible():
       self.parent.nodeFilterBox.setVisible(False) 
     else:
       self.parent.nodeFilterBox.setVisible(True) 

  def createPathEdit(self):
    self.treemodel = self.parent.treeModel
    self.model = self.parent.model

    self.connect(self.model, SIGNAL("rootPathChanged"), self.rootpathchanged)
    
    self.completer = kompleter(self.pathedit, self.treemodel, self.model)
    self.pathedit.setCompleter(self.completer)

  def rootpathchanged(self, node):
    path = node.absolute()
    if len(self.history) > 0 and  self.history[len(self.history) - 1] != path:
      if not self.pathInHistory(path, self.history):
        self.history.append(str(node.absolute()))

    self.currentPathId = len(self.history) - 1
    self.changeNavigationState()
    if path != "/":
      path += "/"
    self.pathedit.setCompleter(None)
    self.pathedit.clear()
    self.pathedit.insert(path[1:])
    self.pathedit.setCompleter(self.completer)

  def changeNavigationState(self):
    self.setPrevMenu()
    self.setNextMenu()
    if self.currentPathId > 0:
      self.previous.setEnabled(True)
      self.prevdrop.setEnabled(True)
    else:
      self.previous.setEnabled(False)
      self.prevdrop.setEnabled(False)
    if self.currentPathId < len(self.history) -1:
      self.next.setEnabled(True)
      self.nextdrop.setEnabled(True)
    else:
      self.next.setEnabled(False)
      self.nextdrop.setEnabled(False)


  def bookmark(self):
    bookdiag = bookmarkDialog(self)
    iReturn = bookdiag.exec_()
    if iReturn == 1:
      selectedCategory = bookdiag.getSelectedCategory()
      # Check is is new or existing category
      try:
        i = self.bookmarkCategories.index(selectedCategory)
      except ValueError:
        if not self.createCategory(selectedCategory):
          return

      selectedBookName = selectedCategory
      selectedBookmark = self.vfs.getnode('/Bookmarks/' + str(selectedBookName.toUtf8()))
      for (pnode, state) in self.parent.model.checkedNodes:
        p = self.VFS.getNodeFromPointer(pnode)
        n = VLink(p, selectedBookmark)
        n.__disown__()
        if p.hasChildren and state == 1:
          childrenList = p.children()
          for child in childrenList:
	    c = VLink(child, n)
	    c.__disown__()
      self.parent.model.checkedNodes.clear()	
      e = DEvent()
      self.VFS.notify(e)

  def attrSelectView(self):
    attrdiag = attrDialog(self)
    iReturn = attrdiag.exec_()
    header_list = attrdiag.selectedAttrs
    for i in range(header_list.count()):
      item = header_list.item(i)
      self.model.header_list.append(item.text())
      self.model.setHeaderData(i + 2, Qt.Horizontal, QVariant(item.text()), Qt.DisplayRole)
      
  def createCategory(self, category):
    if category != "":
      # Create bookmark node in root directory if first creation
#      if len(self.bookmarkCategories) == 0:
#        self.bookmarkNode = Node(str('Bookmarks'))
#        self.bookmarkNode.__disown__()
#        root = self.vfs.getnode('/')
#        root.addChild(self.bookmarkNode)

      newNodeBook = Node(str(category.toUtf8()))
      newNodeBook.__disown__()
      self.bookmarkNode.addChild(newNodeBook)
      self.bookmarkCategories.append(category)
      return True
    else:
      return False

  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.retranslateUi(self)
    else:
      QWidget.changeEvent(self, event)

class attrDialog(QDialog, Ui_SelectAttr):
  """
  This class is designed to let users chose which attributes they want to display.
  """
  def __init__(self, nodeviewbox):
    QDialog.__init__(self, nodeviewbox)
    self.setupUi(self)
    model = nodeviewbox.model
    self.initAttrs(model)
    self.connect(self.addAttr, SIGNAL("clicked()"), self.addAttrToList)
    self.connect(self.removeAttr, SIGNAL("clicked()"), self.removeAttrFromList)
    self.connect(self.buttonBox, SIGNAL("accepted()"), self.buttonClicked)

  def buttonClicked(self):
    self.hide()

  def initAttrs(self, model):
    nodes = model.node_list
    node = nodes[0]
    if node == None:
      return
    module = node.fsobj()
    if module == None:
      return
    attrs = node.attributes()[module.name].value()
    attrs.thisown = False
    for j in model.header_list:
      self.selectedAttrs.addItem(j)
    for i in attrs:
      if (attrs[i].type() != typeId.Map) and (attrs[i].type() != typeId.List):
        try:
          model.header_list.index(i)
        except:
          self.allAttrs.addItem(i)
    model.header_list = []

  def addAttrToList(self):
    attr = self.allAttrs.currentItem()
    if attr == None:
      return
    if attr.text().length() != 0:
      row = self.allAttrs.currentRow()
      self.allAttrs.takeItem(row)
      self.selectedAttrs.addItem(attr.text())

  def removeAttrFromList(self):
    attr = self.selectedAttrs.currentItem()
    if attr == None:
      return
    if attr.text().length() != 0:
      row = self.selectedAttrs.currentRow()
      self.selectedAttrs.takeItem(row)
      self.allAttrs.addItem(attr.text())

  def changeEvent(self, event):
    """
    Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.retranslateUi(self)
    else:
      QDialog.changeEvent(self, event)

class bookmarkDialog(QDialog, Ui_AddBookmark):
  def __init__(self, nodeviewbox):
    QDialog.__init__(self, nodeviewbox)
    self.setupUi(self)
    self.nodeviewbox = nodeviewbox
    self.categories = self.nodeviewbox.bookmarkCategories
    self.initShape()

  def initShape(self):
    self.connect(self.newBox, SIGNAL("clicked()"), self.createCategoryBack)
    self.connect(self.existBox, SIGNAL("clicked()"), self.existingCategoryBack)
    
    for cat in self.categories:
      self.catcombo.addItem(cat)
    
    if len(self.categories) != 0:
      self.newBox.setChecked(True)
      self.existBox.setVisible(True)
    else:
      self.existBox.setVisible(False)

  def getSelectedCategory(self):
    if self.newBox.isChecked():
      return self.catname.text()
    else:
      return self.catcombo.currentText()

  def createCategoryBack(self):
    if self.existBox.isChecked():
      self.newBox.setChecked(True)
      self.existBox.setChecked(False)
    else:
      self.newBox.setChecked(True)

  def existingCategoryBack(self):
    if self.newBox.isChecked():
      self.existBox.setChecked(True)
      self.newBox.setChecked(False)
    else:
      self.existBox.setChecked(True)

  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.retranslateUi(self)
    else:
      QDialog.changeEvent(self, event)
        
class kompleter(QCompleter):
    def __init__(self, parent, treemodel, model):
      QCompleter.__init__(self, treemodel) 
      self.init(parent, model, treemodel)

    def init(self, parent, model, treemodel):
      self.parent = parent
      self.model = model
      self.treemodel = treemodel
      
      self.setModel(self.treemodel)
      self.setCompletionMode(QCompleter.PopupCompletion)
      self.setCompletionRole(Qt.DisplayRole)
      self.setCaseSensitivity(Qt.CaseInsensitive)

    def splitPath(self, path):
      return path.split('/')

    def pathFromIndex(self, modelindex, node = None):
      if modelindex != None:
        node = self.treemodel.VFS.getNodeFromPointer(modelindex.internalId())
      
        abspath = node.absolute()
        self.model.setRootPath(node, 1)
        abspath += "/"
        return QString(abspath[1:])


