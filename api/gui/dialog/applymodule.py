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
#  Jeremy MOUNIER <jmo@arxsys.fr>
# 

from types import *

from PyQt4.QtGui import QAbstractItemView, QApplication, QCheckBox, QDialog, QGridLayout, QLabel, QMessageBox,QSplitter, QVBoxLayout, QWidget, QDialogButtonBox, QPushButton, QLineEdit, QCompleter, QSortFilterProxyModel, QGroupBox, QFileDialog, QSpinBox, QFormLayout, QHBoxLayout, QStackedWidget, QListWidget, QListWidgetItem
from PyQt4.QtCore import Qt,  QObject, QRect, QSize, SIGNAL, QModelIndex, QString

# CORE
from api.loader import *
from api.env import *
from api.vfs import *
from api.taskmanager.taskmanager import *
from api.type import *

from api.gui.model.vfsitemmodel import  VFSItemModel
from api.gui.widget.nodeview import NodeTreeView

from api.gui.box.nodecombobox import NodeComboBox
from api.gui.box.stringcombobox import StringComboBox
from api.gui.box.boolcombobox import BoolComboBox
from api.gui.box.checkbox import checkBoxWidget
from api.gui.dialog.uiapplymodule import UiApplyModule 

from ui.gui.utils.utils import Utils


class ApplyModule(QDialog,  UiApplyModule):
    def __init__(self,  mainWindow):
        QDialog.__init__(self,  mainWindow)
        UiApplyModule.__init__(self)
        self.setupUi(self)

        self.__mainWindow = mainWindow
        self.loader = loader.loader()
        self.env = env.env()
        self.vfs = vfs.vfs()
        self.initDialog()
        self.initCallback()
        
    def initDialog(self):
        self.initArguments()
        self.vlayout = QVBoxLayout(self)
        self.vlayout.addWidget(self.infoContainer)
        self.vlayout.addWidget(self.argumentsContainer)
        self.vlayout.addWidget(self.buttonBox)

    def initArguments(self):
        self.infoContainer = QGroupBox("Informations", self)
        self.argumentsContainer = QGroupBox("Arguments", self)
        self.valueArgs = {}
    
    def initCallback(self):
        self.connect(self.buttonBox,SIGNAL("accepted()"), self.validateModule)

    def validateModule(self):
        errorArg = []
        for i in self.valueArgs :
            if not i.optional :
                if i.type == "node" :
                    node = self.vfs.getnode(str(self.valueArgs[i].text()))
                    #node = self.valueArgs[i].currentNode()
                    if node is None :
                        errorArg.append(i)
                else :
                    if i.type != "int":
                        value = str(self.valueArgs[i].currentText())
                        if value == "" :
                            errorArg.append(i)
                    else:
                        value = self.valueArgs[i].value()
        if len(errorArg) > 0:
            QMessageBox.warning(self, self.tr("ApplyModule", "Missing Arguments"), self.tr("ApplyModule", "There are missing arguments."))
        else:
            self.accept()
    
    def initAllInformations(self, nameModule, typeModule, nodesSelected):
        self.__nodesSelected = nodesSelected
        self.currentModName = str(nameModule)

        infolayout = QFormLayout()

        infolayout.addRow("Module", QLabel(nameModule))
        infolayout.addRow("Type", QLabel(typeModule))
        infolayout.addRow("Description", QLabel(self.loader.modules[str(nameModule)].conf.description))
        self.infoContainer.setLayout(infolayout)

        args = Utils.getArgs(str(nameModule))
        self.createArgShape(args)
    
    def createArgShape(self, args):
        self.argslayout = QHBoxLayout()
        self.stackedargs = QStackedWidget()
        self.listargs = QListWidget()

        self.connect(self.listargs, SIGNAL("currentItemChanged(QListWidgetItem*,QListWidgetItem*)"), self.argChanged)

        for arg in args:
            self.createArgument(arg)

        self.argslayout.addWidget(self.listargs)
        self.argslayout.addWidget(self.stackedargs)

        self.argumentsContainer.setLayout(self.argslayout)

    def createArgument(self, arg):
        warg = QWidget()
        arglayout = QFormLayout()
    
        widget = self.getWidgetFromType(arg)

        if arg.optional :
            checkBox =  checkBoxWidget(arglayout, widget)
            arglayout.addRow("Activate", checkBox)

        arglayout.addRow("Type", QLabel(str(arg.type)))
        arglayout.addRow("Description", QLabel(str(arg.description)))
        arglayout.addRow(str(arg.name), widget)

        warg.setLayout(arglayout)
        self.stackedargs.addWidget(warg)
        argitem = QListWidgetItem(str(arg.name), self.listargs)

    def argChanged(self, curitem, previtem):
        self.stackedargs.setCurrentIndex(self.listargs.row(curitem))

    def getWidgetFromType(self, arg):
        list = self.env.getValuesInDb(arg.name, arg.type)
        if arg.type == "node" :
            widget = QLineEdit()
            self.valueArgs[arg] = widget
            button = browseButton(self.argumentsContainer, widget, arg.name, 0)
            # Check if a node is selected
            currentNode = self.__mainWindow.nodeBrowser.currentNode()
            if currentNode != None:
                widget.clear()
                widget.insert(currentNode.absolute())
            w = QWidget()
            wl = QHBoxLayout()
            wl.addWidget(widget)
            wl.addWidget(button)
            w.setLayout(wl)
            return w
        elif arg.type == "int":
            widget = QSpinBox()
            widget.setRange(-(2**31), (2**31)-1)
            self.valueArgs[arg] = widget
            return widget
        elif arg.type == "string":
            widget = StringComboBox(self.argumentsContainer)
            widget.setEditable(True)
            for i in range(0, len(list)) :
                widget.addPath(list[i])
            self.valueArgs[arg] = widget
            return widget
        elif arg.type == "path" :
            widget = StringComboBox(self.argumentsContainer)
            widget.setEditable(True)
            for i in range(0, len(list)) :
                widget.addPath(list[i])
            self.valueArgs[arg] = widget
            button = browseButton(self.argumentsContainer,  widget, arg.name, 1)
            w = QWidget()
            wl = QHBoxLayout()
            wl.addWidget(widget)
            wl.addWidget(button)
            w.setLayout(wl)
            return w
        elif arg.type == "bool" :
            widget = BoolComboBox(self.argumentsContainer)
            self.valueArgs[arg] = widget
            return widget

    def getArguments(self):
        self.arg = self.env.libenv.argument("gui_input")
        self.arg.thisown = 0
        for i in self.valueArgs :
            if not i.optional or self.valueArgs[i].isEnabled():
                if i.type == "node" :
                    self.arg.add_node(str(i.name), self.vfs.getnode(str(self.valueArgs[i].text())))
                else :
                    if i.type == "path" :
                        value = str(self.valueArgs[i].currentText())
                        self.arg.add_path(str(i.name), str(value))
                    elif i.type == "int" :
                        value = self.valueArgs[i].value()
                        self.arg.add_int(str(i.name), value)
                    elif i.type == "string" :
                        value = str(self.valueArgs[i].currentText())
                        self.arg.add_string(str(i.name), value)       
                    elif i.type == "bool" :
                        if value == "True" :
                            value = 1
                        else :
                            value = 0
                        self.arg.add_bool(str(i.name), int(value, 10))
        self.taskmanager = TaskManager()
        modules = self.currentModuleName()
        self.taskmanager.add(str(modules), self.arg, ["thread", "gui"])
        return

    def openApplyModule(self,  nameModule = None, typeModule = None, nodesSelected = None):
        if(self.isVisible()):
            QMessageBox.critical(self, "Erreur", u"This box is already open")
        else:
            self.initAllInformations(nameModule, typeModule,  nodesSelected)
            iReturn = self.exec_()
            if iReturn :
                script = nameModule
                arg = self.getArguments()

    def currentModuleName(self):
        return self.currentModName
    
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


# vtype 0 Normal, 1 VFS
class browseButton(QPushButton):
    def __init__(self, parent, targetResult, arg_name, vtype = 0):
        QPushButton.__init__(self,  parent)
        self.targetResult = targetResult
        self.vtype = vtype
        self.setObjectName("Button" + arg_name)
        self.setText(self.tr("Browse", "Browse"))
        self.setFixedSize(QSize(80,  28))
        self.connect(self,  SIGNAL("clicked()"), self.click)
        
    def click(self):
        if self.vtype == 1:
            sFileName = QFileDialog.getOpenFileName(self, self.tr("BrowserButton", "Add Dump"),  "/home")
            if (sFileName) :
                self.targetResult.addPathAndSelect(sFileName)
        else:
            BrowseVFSDialog = VFSDialog()
            iReturn = BrowseVFSDialog.exec_()
            if iReturn :
                node = BrowseVFSDialog.getSelectedNode()
                if node :
                    self.targetResult.clear()
                    self.targetResult.insert(node.absolute())
                    
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


class pathEdit(QLineEdit):
    def __init__(self, parent):
        QLineEdit.__init__(self,  parent) 
        self.init(parent)

    def init(self, parent):
        self.parent = parent
        self.node = None

    def currentNode(self):
        return self.node

    def setCurrentNode(self, node):
        self.node = node


    def addModel(self):
        self.treeModel = VFSItemModel(self)
        self.treeModel.setRootPath(self.vfs.getnode("/"))
        self.treeProxyModel = NodeTreeProxyModel()
        self.treeProxyModel.setSourceModel(self.treeModel)

    def initCompleter(self):
        self.completer = QCompleter(self)
        self.completer.setModel(self.treeProxyModel)
        self.completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.setCompleter(self.completer)

