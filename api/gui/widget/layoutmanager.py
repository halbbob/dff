# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009 ArxSys
# 
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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 

from PyQt4.QtGui import *
from PyQt4.QtCore import *

import os
import types

from api.vfs import *
from api.vfs.libvfs import VFS
from api.types.libtypes import typeId
from api.gui.widget.nodeview import NodeTableView, NodeLinkTreeView
from api.gui.model.vfsitemmodel import  VFSItemModel, TreeModel
from ui.gui.resources.ui_nodeviewbox import Ui_NodeViewBox
from api.gui.widget.completer import CompleterWidget


class NavigationBar(QWidget, Ui_NodeViewBox):
    def __init__(self, parent=None):
        QWidget.__init__(self)
        self.vfs = vfs.vfs()
        self.setupUi(self)
        self.button = {}
        self.history = []
        self.history.append("/")
        self.viewbox.hide()
        self.attrSelect.hide()
        self.addToBookmark.hide()
        self.checkboxAttribute.hide()
        self.search.hide()
        self.imagethumb.hide()
        self.thumbSize.hide()
        self.currentPathId = -1
        self.connect(self.previous, SIGNAL("clicked()"), self.moveToPrevious)
        self.setPrevDropButton()
        self.connect(self.next, SIGNAL("clicked()"), self.moveToNext)
        self.setNextDropButton()
        self.connect(self.top, SIGNAL("clicked()"), self.moveToTop)
        self.connect(self.root, SIGNAL("clicked()"), self.goHome)
        self.currentNode = self.vfs.getnode("/")
        self.completerWidget = CompleterWidget()
        self.pathedit.addWidget(self.completerWidget)
        self.completerWidget.setText("/")
        self.connect(self.completerWidget, SIGNAL("returnPressed()"), self.completerChanged)
    

    def completerChanged(self):
        path = self.completerWidget.text()
        node = self.vfs.getnode(str(path))
        if node:
            self.emit(SIGNAL("pathChanged"), node)
            self.updateCurrentPath(node)


    def updateCurrentPath(self, node):
        self.currentNode = node
        path = node.absolute()
        if len(self.history) > 0 and  self.history[len(self.history) - 1] != path:
            if not self.pathInHistory(path, self.history):
                self.history.append(str(node.absolute()))
        self.currentPathId = len(self.history) - 1
        self.changeNavigationState()


    def moveToTop(self):
        if self.currentNode != None:
            self.currentNode = self.currentNode.parent()
            self.emit(SIGNAL("pathChanged"), self.currentNode)
            self.changeNavigationState()
            self.completerWidget.pathChanged(self.currentNode.absolute())


    def moveToPrevious(self):
        if self.currentPathId > 0:
            self.currentPathId = self.currentPathId - 1
            path = self.history[self.currentPathId]
            self.currentNode = self.vfs.getnode(path)
            self.emit(SIGNAL("pathChanged"), self.currentNode)
            self.completerWidget.pathChanged(self.currentNode.absolute())
            self.changeNavigationState()


    def moveToNext(self):
        if self.currentPathId < len(self.history) - 1:
            self.currentPathId = self.currentPathId + 1
            path = self.history[self.currentPathId]
            self.currentNode = self.vfs.getnode(path)
            self.emit(SIGNAL("pathChanged"), self.currentNode)
            self.completerWidget.pathChanged(self.currentNode.absolute())
            self.changeNavigationState()


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
        self.currentNode = self.vfs.getnode(str(action.text()))
        self.emit(SIGNAL("pathChanged"), self.currentNode)
        self.completerWidget.pathChanged(self.currentNode.absolute())


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
        self.currentNode = self.vfs.getnode(str(action.text()))
        self.emit(SIGNAL("pathChanged"), self.currentNode)
        self.completerWidget.pathChanged(self.currentNode.absolute())


    def goHome(self):
        self.currentNode = self.vfs.getnode("/")
        self.emit(SIGNAL("pathChanged"), self.currentNode)
        self.completerWidget.pathChanged(self.currentNode.absolute())


    def changeNavigationState(self):
        self.setPrevMenu()
        self.setNextMenu()
        if self.currentPathId > 0:
            self.previous.setEnabled(True)
            self.prevdrop.setEnabled(True)
        else:
            self.previous.setEnabled(False)
            self.prevdrop.setEnabled(False)
        if self.currentPathId < len(self.history) - 1:
            self.next.setEnabled(True)
            self.nextdrop.setEnabled(True)
        else:
            self.next.setEnabled(False)
            self.nextdrop.setEnabled(False)


class DialogNodeBrowser(QDialog):
    def __init__(self, parent=None):
        QDialog.__init__(self, parent)
        self.title = QLabel("Select a node in the Virtual File System :")
        self.vfs = vfs.vfs()
        self.VFS = VFS.Get()
        self.createLayout()
        self.createModels()
        self.createViews()
        self.createButtons()


    def createLayout(self):
        self.navBar = NavigationBar(self)
        self.baseLayout = QVBoxLayout(self)
        self.baseLayout.setMargin(0)
        self.baseLayout.setSpacing(0)
        self.splitterLayout = QSplitter(self)
        self.splitterLayout.setMinimumWidth(640)
        self.baseLayout.addWidget(self.navBar)
        self.baseLayout.addWidget(self.splitterLayout)
        self.setLayout(self.baseLayout)


    def createModels(self):
        self.treeModel = TreeModel(self)
        self.tableModel = VFSItemModel(self)
        self.treeModel.setRootPath(self.vfs.getnode("/"))
        self.tableModel.setRootPath(self.vfs.getnode("/"))
        self.tableModel.connect(self.navBar, SIGNAL("pathChanged"), self.tableModel.setRootPath)


  
    def createViews(self):
        self.treeView = NodeLinkTreeView(self)
        self.treeView.setModel(self.treeModel)

        self.connect(self.treeView, SIGNAL("nodeTreeClicked"), self.nodeTreeClicked)
        self.splitterLayout.addWidget(self.treeView)

        self.tableView = NodeTableView(self)
        self.tableView.setModel(self.tableModel)
        self.connect(self.tableView, SIGNAL("nodeDoubleClicked"), self.nodeDoubleClicked)
        self.splitterLayout.addWidget(self.tableView)


    def nodeTreeClicked(self, mouseButton, node, index = None):
        self.treeView.model().setRootPath(node)
        

    def nodeDoubleClicked(self, mouseButton, node, index = None):
        if node == None:
            return
        if node.hasChildren() or node.isDir():
            self.tableView.model().setRootPath(node)
            self.navBar.updateCurrentPath(node)


    def createButtons(self):
        self.buttonBox = QDialogButtonBox()
        self.buttonBox.setStandardButtons(QDialogButtonBox.Cancel|QDialogButtonBox.Ok)
        self.connect(self.buttonBox, SIGNAL("accepted()"),self.accept)
        self.connect(self.buttonBox, SIGNAL("rejected()"),self.reject)
        self.baseLayout.addWidget(self.buttonBox)
        

    def getSelectedNodes(self):
        indexes = self.tableView.selectionModel().selectedRows()
        nodes = []
        for index in indexes:
            if index.isValid():
                nodes.append(self.VFS.getNodeFromPointer(index.internalId()))
        return nodes


    def getSelectedNode(self):
        index = self.tableView.selectionModel().currentIndex()
        node = None
        if index.isValid():
            node = self.VFS.getNodeFromPointer(index.internalId())
        return node


    def setSelectionMode(self, mode):
        self.tableView.setSelectionMode(mode)


    def changeEvent(self, event):
        """ Search for a language change event
        
        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.model.translation()
        else:
            QWidget.changeEvent(self, event)


class layoutManager(QWidget):
    '''Create a layout manager which will help widget creation and data managment
    The system work with a key / value system and return python type data (ex: str, int, long, list, tupple, etc..)
    '''
    def __init__(self, displaykey=False):
        QWidget.__init__(self)
        self.layout = QFormLayout()
        self.layout.setMargin(0)
        self.widgets = {}
        self.displaykey = displaykey
        self.setLayout(self.layout)
        self.translation()


    def overwriteKeys(self, key):
        '''
        Check if inserted key already exists in the layout system
        '''
        for k, v in self.widgets.iteritems():
            if k == key:
                return True
        return False

    def addBool(self, key, state = False):
        '''
        Create a non-exclusive checkbox widget and add it into the layout. It permit you to create Bool data representations
        '''
        if not self.overwriteKeys(key):
            if type(key).__name__=='str':
                w = QCheckBox(key)
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
            else:
                return -1
        else:
            return -1
        return 1

    def addList(self, key, predefs, editable=False):
        if len(predefs) > 0 and not self.overwriteKeys(key):
            # Check if value list has the same type
            if type(key) == types.StringType:
                w = QComboBox()
                w.setEditable(editable)
                w.setValidator(QIntValidator())
                for value in predefs:
                    if type(value).__name__=='str':
                        if w.findText(value) == -1:
                            w.addItem(value)
                    elif type(value).__name__=='int':
                        if w.findText(str(value)) == -1:
                            w.addItem(str(value))
                    else:
                        return -1
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else: 
                return -1
        else:
            return -1

    def addSingleArgument(self, key, predefs, typeid, editable=False):
        if not self.overwriteKeys(key):
            if type(key) == types.StringType:
                if len(predefs) > 0:
                    w = QComboBox()
                    w.setEditable(editable)
                    for value in predefs:
                        w.addItem(value.toString())
                else:
                    w = QLineEdit()
                    if typeid not in (typeId.String, typeId.Char, typeId.Node, typeId.Path):
                        w.insert("0")
                    w.setReadOnly(not editable)
                w.setValidator(fieldValidator(self, typeid))
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else: 
                return -1
        else:
            return -1

    def addString(self, key, value=""):
        if not self.overwriteKeys(key):
            if type(key).__name__=='str':
                w = QLineEdit()
                w.insert(value)
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else:
                return -1
        else:
            return -1
    
    def addText(self, key,  value=""):
        if not self.overwriteKeys(key):
            if type(key).__name__=='str':
                w = QTextEdit()
                w.setPlainText(value)
                if not self.displaykey:
                    self.layout.addRow(w)
                else:
                    self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else:
                return -1
        else:
            return -1

    def addListArgument(self, key, typeid, predefs, editable=False):
        if not self.overwriteKeys(key) and type(key) == types.StringType:
            w = multipleListWidget(self, typeid, predefs, editable)
            if not self.displaykey:
                self.layout.addRow(w)
            else:
                self.layout.addRow(key, w)
            self.widgets[key] = w.valuelist
            return 1
        else:
            return -1

    def addPathList(self, key, typeid, predefs, selectednodes):
        if not self.overwriteKeys(key) and type(key).__name__=='str':
            layout = QVBoxLayout()
            listpathcontainer = QListWidget()

            if len(predefs) > 0:
                if not self.checkUnifiedTypes(predefs):
                    return -1
                for predef in predefs:
                    listpathcontainer.insertItem(listpathcontainer.count() + 1, str(predef))
            if len(selectednodes) > 0:
                if typeid == typeId.Node:
                    for node in selectednodes:
                        listpathcontainer.insertItem(listpathcontainer.count() + 1, node.absolute())           

            hbox = QHBoxLayout()
            buttonbox = QDialogButtonBox()
            if typeid == typeId.Path:
                combo = QComboBox()
                combo.addItem(self.inputFile)
                combo.addItem(self.inputDirectory)
            if typeid == typeId.Path:
                add = addLocalPathButton(key, listpathcontainer, combo)
            else:
                add = addLocalPathButton(key, listpathcontainer, nodetype=True)
            buttonbox.addButton(add, QDialogButtonBox.ActionRole)
            rm = rmLocalPathButton(listpathcontainer)
            buttonbox.addButton(rm, QDialogButtonBox.ActionRole)
            hbox.addWidget(buttonbox, 3, Qt.AlignLeft)
            if typeid == typeId.Path:
                hbox.addWidget(combo, 1, Qt.AlignRight)
            layout.addLayout(hbox, 0)
            layout.addWidget(listpathcontainer, 2)

            if not self.displaykey:
                self.layout.addRow(layout)
            else:
                self.layout.addRow(key, layout)
            self.widgets[key] = listpathcontainer
            return 1
        else:
            return -1

    def addPath(self, key, typeid, predefs, selectednodes, editable=False):
        if not self.overwriteKeys(key) and type(key).__name__=='str':
            vbox = QVBoxLayout()
            if typeid == typeId.Path:
                combo = QComboBox()
                combo.addItem(self.inputFile)
                combo.addItem(self.inputDirectory)
                vbox.addWidget(combo)
            layout = QHBoxLayout()
            if len(predefs) > 0 or len(selectednodes) > 0:
                pathcontainer = QComboBox()
                pathcontainer.setEditable(editable)
                for value in predefs:
                    if typeid == typeId.Node:
                        pathcontainer.addItem(value.value().name())
                    else:
                        pathcontainer.addItem(value.toString())
                if typeid == typeId.Node:
                    for node in selectednodes:
                        pathcontainer.addItem(node.absolute())
            else:
                pathcontainer = QLineEdit()
                pathcontainer.setReadOnly(not editable)
            if typeid == typeId.Path:
                browse = addLocalPathButton(key, pathcontainer, inputchoice=combo)
            else:
                browse = addLocalPathButton(key, pathcontainer, nodetype=True)
            layout.addWidget(pathcontainer, 2)
            layout.addWidget(browse, 0)
            vbox.addLayout(layout)
            if not self.displaykey:
                self.layout.addRow(vbox)
            else:
                self.layout.addRow(key, vbox)
            self.widgets[key] = pathcontainer
            return 1
        else:
            return -1


    def checkUnifiedTypes(self, values):
        if len(values) == 0:
            return
        vtype = type(values[0]).__name__
        for v in values:
            if type(v).__name__!=vtype:
                return False
        return True

    def get(self, key):
        for k, v in self.widgets.iteritems():
            if k == key:
                if isinstance(self.widgets[k], QLineEdit):
                    return str(v.text().toUtf8())
                elif isinstance(self.widgets[k], QListWidget):
                    items = []
                    for index in xrange(self.widgets[k].count()): 
                        items.append(str(self.widgets[k].item(index).text().toUtf8())) 
                    return items
                elif isinstance(self.widgets[k], QCheckBox):
                    state = self.widgets[k].checkState()
                    if state == Qt.Unchecked:
                        return False
                    else:
                        return True
                elif isinstance(self.widgets[k], QTextEdit):
                    return str(self.widgets[k].toPlainText().toUtf8())
                elif isinstance(self.widgets[k], QComboBox):
                    return str(self.widgets[k].currentText().toUtf8())
                else:
                    return -1


    def translation(self):
        self.inputFile = self.tr("File")
        self.inputDirectory = self.tr("Directory")


    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.translation()
        else:
            QWidget.changeEvent(self, event)


class fieldValidator(QRegExpValidator):
    def __init__(self, parent, typeid):
        QRegExpValidator.__init__(self, parent)
        self.typeid = typeid
        self.init()

    def init(self):
        if self.typeid in (typeId.Int16, typeId.Int32, typeId.Int64):
            exp = "^(\+|-)?\d+$"
        elif self.typeid in (typeId.UInt16, typeId.UInt32, typeId.UInt64):
            exp = "^\d+$"
        else:
            exp = "^\D+$"
        regexp = QRegExp(exp)
        regexp.setCaseSensitivity(Qt.CaseInsensitive)
        self.setRegExp(regexp)


class multipleListWidget(QWidget):
    def __init__(self, parent, typeid, predefs, editable):
        QWidget.__init__(self)
        self.parent = parent
        self.typeid = typeid
        self.editable = editable
        self.predefs = predefs
        self.init()

    def init(self):
        self.vbox = QVBoxLayout()
        self.vbox.setSpacing(5)
        self.vbox.setMargin(0)
        self.createHeader()
        self.valuelist = QListWidget()
        self.vbox.addWidget(self.valuelist)
        self.setLayout(self.vbox)

    def createHeader(self):
        self.whead = QWidget()
        self.headerlayout = QHBoxLayout()
        self.headerlayout.setSpacing(0)
        self.headerlayout.setMargin(0)
        if self.typeid in (typeId.Node, typeId.Path) and self.editable:
            self.addPath()
        else:
            self.addSingleArgument()

        self.addButton = QPushButton(QIcon(":add.png"), "")
        self.rmButton = QPushButton(QIcon(":del_dump.png"), "")
        self.addButton.setIconSize(QSize(16, 16))
        self.rmButton.setIconSize(QSize(16, 16))

        self.connect(self.addButton, SIGNAL("clicked()"), self.addParameter)
        self.connect(self.rmButton, SIGNAL("clicked()"), self.rmParameter)

        self.headerlayout.addWidget(self.addButton, 0)
        self.headerlayout.addWidget(self.rmButton, 0)
        self.whead.setLayout(self.headerlayout)
        self.vbox.addWidget(self.whead)

    def addParameter(self):
        if isinstance(self.container, QComboBox):
            item = self.container.currentText()
        else:
            item = self.container.text()
        if len(self.valuelist.findItems(item, Qt.MatchExactly)) == 0:
            self.valuelist.insertItem(self.valuelist.count() + 1, item) 

    def rmParameter(self):
        selected = self.valuelist.selectedItems()
        for item in selected:
            row = self.valuelist.row(item)
            self.valuelist.takeItem(row)        

    def addSingleArgument(self):
        if len(self.predefs) > 0:
            self.container = QComboBox()
            for value in self.predefs:
                if self.typeid == typeId.Node:
                    self.container.addItem(value.value().name())
                else:
                    self.container.addItem(value.toString())
                self.container.setEditable(self.editable)
        else:
            self.container = QLineEdit()
            self.container.setReadOnly(self.editable)
        self.headerlayout.addWidget(self.container, 2)

    def addPath(self):
        if len(self.predefs) > 0:
            self.container = QComboBox()
            self.container.setReadOnly(False)
            for value in self.predefs:
                self.container.addItem(value.toString())
        else:
            self.container = QLineEdit()
            self.container.setReadOnly(False)
            if self.typeid == typeId.Path:
                browse = addLocalPathButton(key, self.container, isdir=False)
            else:
                browse = addLocalPathButton(key, self.container, isdir=False, nodetype=True)
        self.headerlayout.addWidget(self.container, 2)
        self.headerlayout.addWidget(browse, 0)

    def addPredefValue(self):
        selected = self.predefs.selectedItems()
        for item in selected:
            self.valuelist.insertItem(self.valuelist.count() + 1, item.text())



class addLocalPathButton(QPushButton):
    def __init__(self, key, container, inputchoice=None, nodetype=False):
        if isinstance(container, QListWidget):
            QPushButton.__init__(self, QIcon(":add.png"), "")
        else:
            QPushButton.__init__(self, QIcon(":folder.png"), "...")
        self.setIconSize(QSize(16, 16))
        self.inputcombo = inputchoice
        self.ckey = key
        self.container = container
        self.parent = container
        self.nodetype = nodetype
#        self.listpath = listpath
#        self.ckey = ckey
        self.connect(self, SIGNAL("clicked()"), self.browse)
        
    def browse(self):
        title = "Load " + str(self.ckey)
        if not self.nodetype:
            if self.inputcombo and self.inputcombo.currentIndex() == 0:
                if isinstance(self.container, QListWidget):
                    sFileName = QFileDialog.getOpenFileNames(self.parent, title, os.path.expanduser('~'))
                    for name in sFileName:
                        item = QListWidgetItem(str(name), self.container)
                elif isinstance(self.container, QLineEdit):
                    sFileName = QFileDialog.getOpenFileName(self.parent, title, os.path.expanduser('~'))
                    self.container.clear()
                    self.container.insert(sFileName)
                else:
                    return -1
            else:
                sFileName = QFileDialog.getExistingDirectory(self.parent, title, os.path.expanduser('~'), QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks)
                if isinstance(self.container, QListWidget):
                    item = QListWidgetItem(str(sFileName), self.container)
                else:
                    self.container.insert(sFileName)
        else:
            BrowseVFSDialog = DialogNodeBrowser(self)
            if isinstance(self.container, QListWidget) or isinstance(self.container, QComboBox):
                BrowseVFSDialog.setSelectionMode(QAbstractItemView.ExtendedSelection)
                iReturn = BrowseVFSDialog.exec_()
                if iReturn :
                    nodes = BrowseVFSDialog.getSelectedNodes()
                    index = 0
                    if len(nodes):
                        for node in nodes:
                            self.container.insertItem(index, node.absolute())
                            index += 1
                        if isinstance(self.container, QListWidget):
                            self.container.setCurrentItem(self.container.item(0))
                        else:
                            self.container.setCurrentIndex(0)
            else:
                BrowseVFSDialog.setSelectionMode(QAbstractItemView.SingleSelection)
                iReturn = BrowseVFSDialog.exec_()
                if iReturn :
                    node = BrowseVFSDialog.getSelectedNode()
                    if node:
                        self.container.clear()
                        self.container.insert(node.absolute())



class rmLocalPathButton(QPushButton):
    def __init__(self, container):
        QPushButton.__init__(self, QIcon(":del_dump.png"),"")
        self.setIconSize(QSize(16, 16))
        self.container = container
        self.connect(self, SIGNAL("clicked()"), self.rm)

    def rm(self):
        selected = self.container.selectedItems()
        for item in selected:
            row = self.container.row(item)
            self.container.takeItem(row)

