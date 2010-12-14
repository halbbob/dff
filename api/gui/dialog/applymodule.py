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

from PyQt4.QtGui import QAbstractItemView, QApplication, QCheckBox, QDialog, QGridLayout, QLabel, QMessageBox,QSplitter, QVBoxLayout, QWidget, QDialogButtonBox, QPushButton, QLineEdit, QCompleter, QSortFilterProxyModel, QGroupBox, QFileDialog
from PyQt4.QtCore import Qt,  QObject, QRect, QSize, SIGNAL, QModelIndex

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
from api.gui.box.checkbox import CheckBoxWidgetEnable
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
#        self.vlayout.addWidget(self.label)
#        self.splitter = QSplitter(Qt.Vertical, self)
#        self.splitter.addWidget(self.argumentsContainer)        
        self.vlayout.addWidget(self.infoContainer)
        self.vlayout.addWidget(self.argumentsContainer)
        self.vlayout.addWidget(self.buttonBox)

    def initArguments(self):
        self.infoContainer = QGroupBox("Informations", self)
        self.argumentsContainer = QGroupBox("Arguments", self)
#        self.argumentsContainer = QWidget(self)
        self.gridArgs = QGridLayout(self.argumentsContainer)
        self.labelArgs = {}
        self.valueArgs = {}
        self.checkBoxArgs = {}
        self.hboxArgs = {}
        self.browserButtons = {}
        self.lineEdit = {}
    
    
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
                    value = str(self.valueArgs[i].currentText())
                    if value == "" :
                        errorArg.append(i)
        if len(errorArg) > 0:
            QMessageBox.warning(self, self.tr("ApplyModule", "Missing Arguments"), self.tr("ApplyModule", "There are missing arguments."))
        else:
            self.accept()
    
    def initAllInformations(self, nameModule, typeModule, nodesSelected):
        self.__nodesSelected = nodesSelected
        self.currentModName = str(nameModule)
        
        name = "Module : "
        name += nameModule
        lname = QLabel(name)
        typ = "Type : "
        typ += typeModule
        ltype = QLabel(typ)

        desc = "General Description : "
        desc += self.loader.modules[str(nameModule)].conf.description
        ldesc = QLabel(desc)

        vboxinfo = QVBoxLayout(self.infoContainer)
        vboxinfo.addWidget(lname)
        vboxinfo.addWidget(ltype)
        vboxinfo.addWidget(ldesc)

        # Set argument description
        args = Utils.getArgs(str(nameModule))
#        vars_db = self.env.vars_db
        for arg in args:            
            argdesc = " - "
            argdesc += arg.name
            argdesc += " : "
            argdesc += arg.description
            arglabeldesc = QLabel(argdesc)
            vboxinfo.addWidget(arglabeldesc)


        self.infoContainer.setLayout(vboxinfo)

        self.loadArguments(str(nameModule), str(typeModule))
    
    def loadArguments(self, nameModule, type):
        if self.argumentsContainer == None :
            self.argumentsContainer = QGroupBox("Arguments", self)
#            self.argumentsContainer = QWidget(self)

        iterator = 0
        args = Utils.getArgs(nameModule)

        vars_db = self.env.vars_db
        for arg in args:
            label = QLabel(arg.name + " ( "+ str(arg.type) + " ) " + ":", self.argumentsContainer)
            label.setMinimumSize(QSize(80,  28))
            label.setMaximumSize(QSize(120,  28))
            list = self.env.getValuesInDb(arg.name,  arg.type)
            if arg.type == "node" :
                value = QLineEdit()#pathEdit(self)
                button = browseButton(self.argumentsContainer, value, arg.name, 0)
                # Check if a node is selected
                currentNode = self.__mainWindow.nodeBrowser.currentNode()
                if currentNode != None:
                    value.clear()
                    value.insert(currentNode.absolute())
                    #value.setCurrentNode(currentNode)

            elif arg.type == "int":
                value = StringComboBox(self.argumentsContainer)
                value.setEditable(True)
                for i in range(0, len(list)) :
                    value.addPath(str(list[i]))
                button = None
            
            elif arg.type == "string":
                value = StringComboBox(self.argumentsContainer)
                value.setEditable(True)
                for i in range(0, len(list)) :
                    value.addPath(list[i])
                button = None
                    
            elif arg.type == "path" :
                value = StringComboBox(self.argumentsContainer)
                value.setEditable(True)
                for i in range(0, len(list)) :
                    value.addPath(list[i])
                button = browseButton(self.argumentsContainer,  value, arg.name, 1)
            
            elif arg.type == "bool" :
                value = BoolComboBox(self.argumentsContainer)
                button = None
                    
            if arg.optional :
                checkBox =  CheckBoxWidgetEnable(self.argumentsContainer, label, value,  button)
            else :
                checkBox = None
            
            self.gridArgs.addWidget(label, iterator, 0)
            if value != None :
                self.gridArgs.addWidget(value, iterator, 1)
            if button != None:
                self.gridArgs.addWidget(button, iterator, 2)
            if checkBox != None :
                self.gridArgs.addWidget(checkBox, iterator, 3)

            self.labelArgs[arg] = label
            self.valueArgs[arg] = value
            self.checkBoxArgs[arg] = checkBox
            self.browserButtons[arg] = button
            iterator = iterator + 1

    def currentModuleName(self):
        return self.currentModName

    # get Arguments
    def getArguments(self):
        self.arg = self.env.libenv.argument("gui_input")
        self.arg.thisown = 0
        for i in self.valueArgs :
            if i.type == "node" :
                self.arg.add_node(str(i.name), self.vfs.getnode(str(self.valueArgs[i].text())))
                #self.arg.add_node(str(i.name), self.valueArgs[i].currentNode())
            else :
                value = str(self.valueArgs[i].currentText())
                if i.type == "path" :
                    self.arg.add_path(str(i.name), str(value))
                elif i.type == "int" :
                    self.arg.add_int(str(i.name), int(value))
                elif i.type == "string" :
                    self.arg.add_string(str(i.name), value)            
                elif i.type == "bool" :
                    if value == "True" :
                        value = 1
                    else :
                        value = 0
                    self.arg.add_bool(str(i.name), int(value))
        self.taskmanager = TaskManager()
        modules = self.currentModuleName()
        self.taskmanager.add(str(modules), self.arg, ["thread", "gui"])
        return #self.arg

    def openApplyModule(self,  nameModule = None, typeModule = None, nodesSelected = None):
#        self.deleteAllArguments()
        if(self.isVisible()):
            QMessageBox.critical(self, "Erreur", u"This box is already open")
        else:
            self.initAllInformations(nameModule, typeModule,  nodesSelected)
            iReturn = self.exec_()
        if iReturn :
            script = nameModule
            arg = self.getArguments()
    
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
#        self.node = node
        self.setObjectName("Button" + arg_name)
        self.setText(self.tr("BrowserButton", "Browse"))
        self.setFixedSize(QSize(80,  28))
        self.connect(self,  SIGNAL("clicked()"), self.click)
        
    def click(self):
        if self.vtype == 1:
            sFileName = QFileDialog.getOpenFileName(self, self.tr("BrowserButton", "Add Dump"),  "/home")
            if (sFileName) :
#                self.targetResult.clear()
                self.targetResult.addPathAndSelect(sFileName)
        else:
            BrowseVFSDialog = VFSDialog()
            iReturn = BrowseVFSDialog.exec_()
            if iReturn :
                node = BrowseVFSDialog.getSelectedNode()
                if node :
                    self.targetResult.clear()
                    self.targetResult.insert(node.absolute())
                    #self.targetResult.setCurrentNode(node)
                    
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


# Model For QCompleter

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
#        self.addModel()
#        self.initCompleter()
#        self.initCompleter()

    def init(self, parent):
        self.parent = parent
#        self.setReadOnly(True)
        self.node = None
#        self.vfs = vfs.vfs()

    def currentNode(self):
        return self.node

    def setCurrentNode(self, node):
        self.node = node


    def addModel(self):
        self.treeModel = VFSItemModel(self)
        self.treeModel.setRootPath(self.vfs.getnode("/"))
        self.treeProxyModel = NodeTreeProxyModel()
        self.treeProxyModel.setSourceModel(self.treeModel)
#        self.treeView = NodeTreeView(self)
#        self.treeView.setModel(self.treeProxyModel)
#        self.browserLayout.addWidget(self.treeView)
#        self.connect(self.treeView, SIGNAL("nodeClicked"), self.select)


    def initCompleter(self):
        self.completer = QCompleter(self)
#        self.treeModel = VFSItemModel(self.completer)
#        self.treeModel.setRootPath(self.vfs.getnode("/"))
        self.completer.setModel(self.treeProxyModel)
        self.completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.setCompleter(self.completer)

