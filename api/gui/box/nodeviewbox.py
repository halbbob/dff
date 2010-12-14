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
#  Jeremy Mounier <jmo@digital-forensic.org> 

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *

#from api.gui.widget.nodefilterbox import NodeFilterBox

from api.gui.model.vfsitemmodel import  VFSItemModel
from api.gui.widget.propertytable import PropertyTable
from api.vfs.vfs import vfs, Node, DEvent, VLink
from api.vfs import libvfs

class NodeViewBox(QWidget):
  def __init__(self, parent):
    QWidget.__init__(self)
    self.vfs = vfs()
    self.VFS = libvfs.VFS.Get()
    self.parent = parent
    self.button = {}
    
#    self.bookdiag = bookmarkDialog(self)
    self.bookmarkCategories = []

    self.gridLayout = QHBoxLayout(self)
    self.gridLayout.setAlignment(Qt.AlignLeft)
    self.addPropertyTable()
    self.createButton("top", self.moveToTop, "Previous", ":previous.png")
    self.createButton("root", self.goHome,  "Return to root", ":home.png")

    self.createPathEdit()

    self.createChangeView()
    self.createCheckBoxAttribute()
    self.createButton("add to bookmarks", self.bookmark, "Add to bookmarks",":bookmark_add.png")
    self.createButton("search", self.searchActivated, "Display search engine",":filefind.png")
    self.createButton("imagethumb", self.imagethumbActivated, "Active thumbnails",":image.png")
    self.createThumbSize()

    self.tableActivated()

    self.setLayout(self.gridLayout)

  def createChangeView(self):
    self.viewbox = QComboBox()
    self.viewbox.insertItem(0, QIcon(":view_detailed.png"), "List")
    self.viewbox.insertItem(1, QIcon(":view_icon.png"), "Icons")
    self.viewbox.insertItem(2, QIcon(":view_choose.png"), "Tree")
    
    self.connect(self.viewbox, SIGNAL("activated(int)"), self.viewboxChanged)

    self.gridLayout.addWidget(self.viewbox)

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

  def createButton(self, name, func, tooltip, iconName, iconSize = 32):
    self.button[name] = QPushButton(self)
    self.button[name].setFixedSize(QSize(iconSize, iconSize))
    self.button[name].setFlat(True)
    self.button[name].setToolTip(tooltip)
    self.button[name].setIcon(QIcon(iconName))
    self.button[name].setIconSize(QSize(iconSize, iconSize))
    self.gridLayout.addWidget(self.button[name])
    self.parent.connect(self.button[name], SIGNAL("clicked()"), func)

  def goHome(self):
     self.parent.model.setRootPath(self.vfs.getnode("/"))    

  def createThumbSize(self):
    self.thumbSize = QComboBox()
    self.thumbSize.setMaximumWidth(100)
    self.thumbSize.addItem("Small")
    self.thumbSize.addItem("Medium")
    self.thumbSize.addItem("Large")
    self.thumbSize.setEnabled(False)
    self.parent.connect(self.thumbSize, SIGNAL("currentIndexChanged(QString)"), self.parent.sizeChanged)
    self.gridLayout.addWidget(self.thumbSize)

  def createCheckBoxAttribute(self):
    self.checkboxAttribute = QCheckBox("Attributes", self)
    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.checkboxAttribute.setCheckState(True)
    else:
      self.checkboxAttribute.setChecked(True)
    self.checkboxAttribute.setEnabled(True)
    self.checkboxAttribute.setTristate(False)

    self.connect(self.checkboxAttribute, SIGNAL("stateChanged(int)"), self.checkboxAttributeChanged)
    self.gridLayout.addWidget(self.checkboxAttribute)

  def checkboxAttributeChanged(self, state):
     if state:
       self.propertyTable.setVisible(True)
     else:
        self.propertyTable.setVisible(False)	

  def moveToTop(self):
     parent =  self.parent.model.rootItem.parent()
     self.parent.model.setRootPath(parent)
 
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
#     self.checkboxAttribute.setEnabled(False)
#     self.propertyTable.setVisible(False)
#     self.button["thumb"].setEnabled(True)
     self.thumbSize.setEnabled(False)
#     self.button["table"].setEnabled(False)
  
  def thumbActivated(self):
     self.checkboxAttribute.setEnabled(True)
     if self.checkboxAttribute.isChecked():
       self.propertyTable.setVisible(True)
     else :
        self.propertyTable.setVisible(False)
     self.parent.tableView.setVisible(False)
     self.parent.thumbsView.setVisible(True)
#     self.button["thumb"].setEnabled(False)
     self.thumbSize.setEnabled(True)
#     self.button["table"].setEnabled(True)

  def searchActivated(self):
     if self.parent.nodeFilterBox.isVisible():
       self.parent.nodeFilterBox.setVisible(False) 
     else:
       self.parent.nodeFilterBox.setVisible(True) 

  def createPathEdit(self):
    self.pathedit = QLineEdit(self)

#    self.connect(self.pathedit, SIGNAL("textChanged(QString)"), self.textChanged)

    self.treemodel = self.parent.treeModel
    self.model = self.parent.model

    self.connect(self.model, SIGNAL("rootPathChanged"), self.rootpathchanged)
    
    self.completer = kompleter(self.pathedit, self.treemodel, self.model)
    self.pathedit.setCompleter(self.completer)

#    rootlabel = QLabel("/")
#    self.gridLayout.addWidget(rootlabel)
    self.gridLayout.addWidget(self.pathedit)

  def rootpathchanged(self, node):
    path = node.absolute()
    if path != "/":
      path += "/"

    self.pathedit.setCompleter(None)
    self.pathedit.clear()
    self.pathedit.insert(path[1:])
    self.pathedit.setCompleter(self.completer)

  def bookmark(self):
    bookdiag = bookmarkDialog(self)
    iReturn = bookdiag.exec_()
    if iReturn == 1:
      selectedCategory = bookdiag.getSelectedCategory()
      print selectedCategory
      # Check is is new or existing category
      try:
        i = self.bookmarkCategories.index(selectedCategory)
      except ValueError:
        if not self.createCategory(selectedCategory):
          return

      selectedBookName = selectedCategory
      selectedBookmark = self.vfs.getnode('/Bookmarks/' + str(selectedBookName))
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

  def createCategory(self, category):
    if category != "":
      # Create bookmark node in root directory if first creation
      if len(self.bookmarkCategories) == 0:
        self.bookmarkNode = Node(str('Bookmarks'))
        self.bookmarkNode.__disown__()
        root = self.vfs.getnode('/')
        root.addChild(self.bookmarkNode)

      newNodeBook = Node(str(category))
      newNodeBook.__disown__()
      self.bookmarkNode.addChild(newNodeBook)
      self.bookmarkCategories.append(category)
      return True
    else:
      return False

class bookmarkDialog(QDialog):
  def __init__(self, nodeviewbox):
    QDialog.__init__(self, nodeviewbox)
    self.nodeviewbox = nodeviewbox
    self.categories = self.nodeviewbox.bookmarkCategories
    self.initShape()


  def initShape(self):
    self.mainLayout = QVBoxLayout()
    
    self.setWindowTitle("Add bookmark")
    self.createDecorator()
    self.createGroupBoxs()
#    self.createAddBookmarks()
    self.createButtons()
    self.setLayout(self.mainLayout)

  def createDecorator(self):
    self.head = QHBoxLayout()
    self.spixmap = QPixmap(":bookmark.png")
    self.pixmap = self.spixmap.scaled(42, 42)
    self.lpixmap = QLabel()
    self.lpixmap.setPixmap(self.pixmap)

    self.headlabel = QLabel("Add a bookmark from the Virtual File System")
    
    self.head.addWidget(self.lpixmap)
    self.head.addWidget(self.headlabel)

    self.container = QWidget()
    self.container.setLayout(self.head)

    self.mainLayout.addWidget(self.container)

  def createGroupBoxs(self):
    self.newBox = QGroupBox("Create a new category")
    self.newBox.setCheckable(True)
    self.newBox.setChecked(True)

    self.newformLayout = QFormLayout()
    self.catname = QLineEdit()
    self.newformLayout.addRow("Category name :", self.catname)
    self.newBox.setLayout(self.newformLayout)
    self.connect(self.newBox, SIGNAL("clicked()"), self.createCategoryBack)
    self.mainLayout.addWidget(self.newBox)

    self.existBox = QGroupBox("Add in an existing category")
    self.existBox.setCheckable(True)
    self.existBox.setChecked(False)
    self.connect(self.existBox, SIGNAL("clicked()"), self.existingCategoryBack)
    
    self.existformLayout = QFormLayout()
    self.catcombo = QComboBox()
    for cat in self.categories:
      self.catcombo.addItem(cat)
    self.existformLayout.addRow("Category name :", self.catcombo)
    self.existBox.setLayout(self.existformLayout)
    
    if len(self.categories) != 0:
      self.newBox.setChecked(True)
      self.mainLayout.addWidget(self.existBox)

  def createButtons(self):
    self.buttonbox = QDialogButtonBox()
    self.buttonbox.setStandardButtons(QDialogButtonBox.Cancel|QDialogButtonBox.Ok)
    self.connect(self.buttonbox, SIGNAL("accepted()"),self.accept)
    self.connect(self.buttonbox, SIGNAL("rejected()"),self.reject)

    self.mainLayout.addWidget(self.buttonbox)


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


