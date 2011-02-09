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
from api.gui.model.vfsitemmodel import  VFSItemModel
from api.vfs.libvfs import VFS
from api.gui.widget.nodeview import NodeTreeView
from api.types.libtypes import typeId

class layoutManager(QWidget):
    '''Create a layout manager which will help widget creation and data managment
    The system work with a key / value system and return python type data (ex: str, int, long, list, tupple, etc..)
    '''
    def __init__(self):
        QWidget.__init__(self)
        self.layout = QFormLayout()
        self.layout.setMargin(0)
        self.widgets = {}
        self.setLayout(self.layout)

    def overwriteKeys(self, key):
        '''
        Check if inserted key already exists in the layout system
        '''
        for k, v in self.widgets.iteritems():
            if k == key:
                return True
        return False
    # Create one non-exclusive checkbox
    def addBool(self, key, state = False):
        '''
        Create a non-exclusive checkbox widget and add it into the layout. It permit you to create Bool data representations
        '''
        if not self.overwriteKeys(key):
            if type(key).__name__=='str':
                w = QCheckBox(key)
                self.layout.addRow(w)
                self.widgets[key] = w
            else:
                return -1
        else:
            return -1
        return 1

    # Choice : une valeur parmis plusieurs choix (combobox)
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
                self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else: 
                return -1
        else:
            return -1

    # Choice : une valeur parmis plusieurs choix (combobox)
    def addSingleArgument(self, key, predefs, editable=False):
        if not self.overwriteKeys(key):
            if type(key) == types.StringType:
                if len(predefs) > 0:
                    w = QComboBox()
                    for value in predefs:
                        w.addItem(value.toString())
                else:
                    w = QLineEdit()
                w.setEditable(editable)
                self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else: 
                return -1
        else:
            return -1

    def addInt(self, key, value=0):
        if not self.overwriteKeys(key):
            if type(key).__name__=='str' and type(value).__name__=="int":
                w = QSpinBox()
                w.setValue(value)
                self.layout.addRow(key, w)
                self.widgets[key] = w
                return 1
            else :
                return -1
        else:
            return -1

    def addUInt(self, key, value=0):
        if not self.overwriteKeys(key):
            if type(key).__name__=='str'\
            and (type(value).__name__=="long"\
                 or type(value).__name__=="int"):
                w = QUSpinBox()
                w.setValue(value)
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
                self.layout.addRow(key, w)
 #               self.wtypes[key] = "text"
                self.widgets[key] = w
                return 1
            else:
                return -1
        else:
            return -1

    # create a custom widget with or not with predef values
    # if predef values are set, it will automaticly detect list type
    # be carreful to unify list types in predefs
    # If there is no predef values, specify which one you want to create : 
    #    "str", "int", "long"
    def addListArgument(self, key, typeid, predefs, editable=False):
        if not self.overwriteKeys(key) and type(key) == types.StringType:
            w = multipleListWidget(self, typeid, predefs, editable)
            self.layout.addRow(w)
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
            buttonbox = QDialogButtonBox()
            if typeid == typeId.Path:
                add = addLocalPathButton(key, listpathcontainer, isdir=False)
            else:
                add = addLocalPathButton(key, listpathcontainer, isdir=False, nodetype=True)
            buttonbox.addButton(add, QDialogButtonBox.ActionRole)
            rm = rmLocalPathButton(listpathcontainer)
            buttonbox.addButton(rm, QDialogButtonBox.ActionRole)
            
            layout.addWidget(buttonbox, 0, Qt.AlignLeft)
            layout.addWidget(listpathcontainer, 2)

            self.layout.addRow(layout)
            self.widgets[key] = listpathcontainer
            return 1
        else:
            return -1

    def addPath(self, key, typeid, predefs, editable=False):
        if not self.overwriteKeys(key) and type(key).__name__=='str':
            layout = QHBoxLayout()
#            layout.setSpacing(0)
#            layout.setMargin(0)
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
                pathcontainer.setReadOnly(editable)
            if typeid == typeId.Path:
                browse = addLocalPathButton(key, pathcontainer, isdir=False)
            else:
                browse = addLocalPathButton(key, pathcontainer, isdir=False, nodetype=True)
            layout.addWidget(pathcontainer, 2)
            layout.addWidget(browse, 0)
            self.layout.addRow(key, layout)
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
                    return v.text()
                elif isinstance(self.widgets[k], QSpinBox) or isinstance(self.widgets[k], QUSpinBox):
                    return v.value()
                elif isinstance(self.widgets[k], QListWidget):
                    items = []
                    for index in xrange(self.widgets[k].count()): 
                        items.append(str(self.widgets[k].item(index).text())) 
                    return items
                elif isinstance(self.widgets[k], QCheckBox):
                    state = self.widgets[k].checkState()
                    if state == Qt.Unchecked:
                        return False
                    else:
                        return True
                elif isinstance(self.widgets[k], QTextEdit):
                    return self.widgets[k].toPlainText()
                elif isinstance(self.widgets[k], QComboBox):
                    return self.widgets[k].currentIndex()
                else:
                    return -1

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

########### Custom Widgets ###############
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
        self.treeModel = VFSItemModel(self)
        self.treeModel.setRootPath(self.vfs.getnode("/"))
        self.treeProxyModel = NodeTreeProxyModel()
        self.treeProxyModel.setSourceModel(self.treeModel)
        self.treeView = NodeTreeView(self)
        self.treeView.setMinimumWidth(640)
        self.treeView.setModel(self.treeProxyModel)
        self.connect(self.treeView, SIGNAL("nodeClicked"), self.select)

    def select(self, button, node):
        self.selection = node

    def nodeSelected(self):
        return self.selection


class NodeTreeProxyModel(QSortFilterProxyModel):
  def __init__(self, parent = None):
    QSortFilterProxyModel.__init__(self, parent)
    self.VFS = VFS.Get()  

  def filterAcceptsRow(self, row, parent):
     index = self.sourceModel().index(row, 0, parent) 
     if index.isValid():
	 return True
     return False

  def columnCount(self, parent = QModelIndex()):
     return 1


class addLocalPathButton(QPushButton):
    def __init__(self, key, container, isdir = False, nodetype=False):
        if isinstance(container, QListWidget):
            QPushButton.__init__(self, QIcon(":add.png"), "")
        else:
            QPushButton.__init__(self, QIcon(":folder.png"), "...")
        self.setIconSize(QSize(16, 16))
        self.isdir = isdir
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
            if not self.isdir:
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
                print node.absolute()
                if node :
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

class QUSpinBox(QAbstractSpinBox):
    def __init__(self, parent=None):
        QAbstractSpinBox.__init__(self)
        self.init(parent)
        self.initEdit()

    def init(self, parent):
        #Variables
        self.parent = parent
        self.__minimum = 0
        self.__maximum = 0
        self.__range = 0
        self.__value = 0
        self.__singleStep = 0
        #Functions
        self.setWrapping(True)
#        self.setEnabled(True)

    def initEdit(self):
        self.__edit = self.lineEdit()
        self.__edit.connect(self.__edit, SIGNAL("editingFinished()"), self.editChanged)
#        self.setLineEdit(self.__edit)

    def stepEnabled(self):
        if self.wrapping():
            if self.__value == self.__minimum:
                return self.StepEnabled(QAbstractSpinBox.StepUpEnabled)
            elif self.__value == self.__maximum:
                return self.StepEnabled(QAbstractSpinBox.StepDownEnabled)
            else:
                return self.StepEnabled(QAbstractSpinBox.StepUpEnabled | QAbstractSpinBox.StepDownEnabled)        

    def maximum(self):
        return self.__maximum

    def minimum(self):
        return self.__minimum

    def setMaximum(self, max):
        self.__maximum = max

    def setMinimum(self, min):
        self.__minimum = min

    def setSingleStep(self, step):
        self.__singlStep = step

    def setRange(self, range):
        self.__range = range

    def setValue(self, value):
        self.__value = value
        self.refreshEdit(value)

    def value(self):
        return self.__value

    def singleStep(self):
        return self.__singleStep

    def maximum(self):
        return self.__maximum

    def minimum(self):
        return self.__minimum

    def stepBy(self, step):
        if step < 0:
            if self.__value > self.__minimum:
                self.__value -= 1
                self.refreshEdit(self.__value)
        else:
            if self.__value < self.__maximum:
                self.__value += 1
                self.refreshEdit(self.__value)

    def refreshEdit(self, value):
        self.__edit.clear()
        cvalue = "%.1d" % value
        self.__edit.insert(cvalue)

    def editChanged(self):
        value = self.__edit.text()
        lvalue = value.toULongLong()
        if lvalue[1]:
            if (lvalue[0] <= self.__maximum) and (lvalue[0] >= self.__minimum):
                self.__value = lvalue[0]
                self.refreshEdit(lvalue[0])
            else:
                self.refreshEdit(self.__value)
        else:
            self.refreshEdit(self.__value)






