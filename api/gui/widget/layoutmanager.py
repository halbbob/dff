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
from api.gui.model.vfsitemmodel import TreeModel#, NodeTreeProxyModel
from api.vfs.libvfs import VFS
from api.gui.widget.nodeview import NodeTreeView
from api.types.libtypes import typeId

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
                    if typeid not in (typeId.String, typeId.Char, typeId.Node, typeId.Path):
                        w.addItem("0")
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
#            self.layout.addRow(w)
            if not self.displaykey:
                self.layout.addRow(w)
            else:
                self.layout.addRow(key, w)
            self.widgets[key] = w.valuelist
            return 1
        else:
            return -1

    def addPathList(self, key, typeid, predefs):
        if not self.overwriteKeys(key) and type(key).__name__=='str':
            layout = QVBoxLayout()
            listpathcontainer = QListWidget()

            if len(predefs) > 0:
                if not self.checkUnifiedTypes(predefs):
                    return -1
                for predef in predefs:
                    listpathcontainer.insertItem(listpathcontainer.count() + 1, str(predef))
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

    def addPath(self, key, typeid, predefs, editable=False):
        if not self.overwriteKeys(key) and type(key).__name__=='str':
            vbox = QVBoxLayout()
            if typeid == typeId.Path:
                combo = QComboBox()
                combo.addItem(self.inputFile)
                combo.addItem(self.inputDirectory)
                vbox.addWidget(combo)
            layout = QHBoxLayout()
            if len(predefs) > 0:
                pathcontainer = QComboBox()
                pathcontainer.setEditable(editable)
                for value in predefs:
                    if typeid == typeId.Node:
                        pathcontainer.addItem(value.value().name())
                    else:
                        pathcontainer.addItem(value.toString())
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
            self.retranslateUi(self)
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



class VFSDialog(QDialog):
    def __init__(self):
        QDialog.__init__(self)
        self.initShape()

    def initShape(self):
#        self.vbox = QVBoxLayout(self)
        self.grid = QGridLayout(self)
        self.title = QLabel("Select a node in the Virtual File System :")
        self.vfs = SimpleNodeBrowser(self)

        self.createButtons()
        
        self.grid.addWidget(self.title, 0, 0)
        self.grid.addWidget(self.vfs, 1, 0)
        self.grid.addWidget(self.buttonbox, 2, 0)

    def createButtons(self):
        self.buttonbox = QDialogButtonBox()
        self.buttonbox.setStandardButtons(QDialogButtonBox.Cancel|QDialogButtonBox.Ok)
        self.connect(self.buttonbox, SIGNAL("accepted()"),self.accept)
        self.connect(self.buttonbox, SIGNAL("rejected()"),self.reject)

    def getSelectedNode(self):
        return self.vfs.nodeSelected()

class SimpleNodeBrowser(QWidget):
    def __init__(self, parent):
        QWidget.__init__(self, parent)
        self.type = "filebrowser"
        self.icon = None
        self.name = "nodebrowser"
        self.setObjectName(self.name)

        self.vfs = vfs.vfs()
        
        self.addNodeTreeView()
        self.selection = None
        
        self.box = QGridLayout()
        self.box.addWidget(self.treeView, 0,0)
        self.setLayout(self.box)

    def addNodeTreeView(self):
        self.treeModel = TreeModel(self, False)
        self.treeModel.setRootPath(self.vfs.getnode("/"))
        self.treeProxyModel = NodeTreeProxyModel()
        self.treeProxyModel.setSourceModel(self.treeModel)
        self.treeView = NodeTreeView(self)
        self.treeView.setMinimumWidth(640)
        self.treeView.setModel(self.treeModel)
        self.connect(self.treeView, SIGNAL("nodeClicked"), self.select)

    def select(self, button, node):
        self.selection = node

    def nodeSelected(self):
        return self.selection


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
            BrowseVFSDialog = VFSDialog()
            iReturn = BrowseVFSDialog.exec_()
            if iReturn :
                node = BrowseVFSDialog.getSelectedNode()
                if node :
                    #self.container.clear()
                  if isinstance(self.container, QListWidget):
                    self.container.insertItem(0, node.absolute())
                    self.container.setCurrentIndex(0)
                  else:
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

