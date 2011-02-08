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
#  Jeremy MOUNIER <jmo@arxsys.fr>
# 

from types import *

from PyQt4.QtGui import QAbstractItemView, QApplication, QCheckBox, QDialog, QGridLayout, QLabel, QMessageBox,QSplitter, QVBoxLayout, QWidget, QDialogButtonBox, QPushButton, QLineEdit, QCompleter, QSortFilterProxyModel, QGroupBox, QFileDialog, QSpinBox, QFormLayout, QHBoxLayout, QStackedWidget, QListWidget, QListWidgetItem, QTextEdit, QPalette, QComboBox, QIntValidator
from PyQt4.QtCore import Qt,  QObject, QRect, QSize, SIGNAL, QModelIndex, QString, QEvent

# CORE
from api.loader import *
#from api.env import *
from api.vfs import *
from api.taskmanager.taskmanager import *
from api.types import *

from api.gui.model.vfsitemmodel import  VFSItemModel
from api.gui.widget.nodeview import NodeTreeView

from api.gui.box.nodecombobox import NodeComboBox
from api.gui.box.stringcombobox import StringComboBox
from api.gui.box.boolcombobox import BoolComboBox
from api.gui.box.checkbox import checkBoxWidget
from ui.gui.resources.ui_applymodule import Ui_applyModule 

from ui.gui.utils.utils import Utils


class ApplyModule(QDialog, Ui_applyModule):
    def __init__(self,  mainWindow):
        super(QDialog, self).__init__()
        self.setupUi(self)

# Hide labels and button used for translators
        self.labActivate.setVisible(False)
        self.labType.setVisible(False)
        self.labDescription.setVisible(False)
        self.browseButton.setVisible(False)

        self.__mainWindow = mainWindow
        self.loader = loader.loader()
        self.env = env.env()
        self.vfs = vfs.vfs()

        self.initArguments()
        self.initCallback()
        self.nameModule = ''


    def initArguments(self):
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
                        v = self.valueArgs[i].currentText().toInt()
                        value = v[0]
        if len(errorArg) > 0:
            QMessageBox.warning(self, self.browseButton.statusTip(), self.browseButton.statusTip())
        else:
            self.accept()
    
    def initAllInformations(self, nameModule, typeModule, nodesSelected):
        self.__nodesSelected = nodesSelected
        self.nameModule = nameModule
        self.currentModName = str(nameModule)

        title = self.windowTitle() + ' ' + str(nameModule)
        self.setWindowTitle(title)

        self.nameModuleField.setText(nameModule)
        self.typeModuleField.setText(typeModule)
        self.textEdit.setText(self.loader.modules[str(nameModule)].conf.description)
        self.textEdit.setFixedHeight(50)

        args = Utils.getArgs(str(nameModule))
        self.createArgShape(args)
    
    def createArgShape(self, args):
        self.connect(self.listargs, SIGNAL("currentItemChanged(QListWidgetItem*,QListWidgetItem*)"), self.argChanged)
        for arg in args:
            self.createArgument(arg)

    def createArgument(self, arg):
        warg = QWidget()
        arglayout = QFormLayout()
    
        widget = self.getWidgetFromType(arg)

        if arg.optional:
            checkBox =  checkBoxWidget(arglayout, widget)
            arglayout.addRow(self.labActivate.text(), checkBox)

        arglayout.addRow(self.labType.text(), QLabel(str(arg.type)))
        tedit = QTextEdit(str(arg.description))
        tedit.setReadOnly(True)
        tedit.setFixedHeight(50)
        arglayout.addRow(self.labDescription.text(), tedit)
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
            button = browseButton(self, widget, arg.name, 0)
            # Check if a node is selected
            currentNode = self.__mainWindow.nodeBrowser.currentNode()
            if currentNode != None:
                widget.clear()
                widget.insert(currentNode.absolute())
            wl = QHBoxLayout()
            wl.addWidget(widget)
            wl.addWidget(button)
            return wl

        elif arg.type == "int":
            widget = QComboBox()
            widget.setEditable(True)
            widget.setValidator(QIntValidator())
            for i in range(0, len(list)) :
                if widget.findText(str(list[i])) == -1:
                    widget.addItem(str(list[i]))
            self.valueArgs[arg] = widget
            return widget

        elif arg.type == "string":
            widget = StringComboBox(self.argumentsContainer)
            widget.setEditable(True)
            for i in range(0, len(list)) :
                print type(list[i])
                widget.addPath(list[i])
            self.valueArgs[arg] = widget
            return widget
        elif arg.type == "path" :
            widget = StringComboBox(self.argumentsContainer)
            widget.setEditable(True)
            for i in range(0, len(list)) :
                widget.addPath(list[i])
            self.valueArgs[arg] = widget
            button = browseButton(self,  widget, arg.name, 1)
            wl = QHBoxLayout()
            wl.addWidget(widget)
            wl.addWidget(button)
            return wl
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
                        value = self.valueArgs[i].currentText().toInt()
                        self.arg.add_int(str(i.name), value[0])
                    elif i.type == "string" :
                        value = str(self.valueArgs[i].currentText())
                        self.arg.add_string(str(i.name), value)       
                    elif i.type == "bool" :
			value = str(self.valueArgs[i].currentText())
                        if value == "True" :
                            value = 1
                        else :
                            value = 0
                        self.arg.add_bool(str(i.name), value)
        self.taskmanager = TaskManager()
        modules = self.currentModuleName()
        self.taskmanager.add(str(modules), self.arg, ["thread", "gui"])
        return

    def openApplyModule(self, nameModule = None, typeModule = None, nodesSelected = None):
        if (self.isVisible()):
            QMessageBox.critical(self, self.browseButton.whatsThis(), self.browseButton.whatsThis())
        else:
            self.initAllInformations(nameModule, typeModule, nodesSelected)
            iReturn = self.exec_()
            if iReturn:
                script = nameModule
                arg = self.getArguments()

    def currentModuleName(self):
        return self.currentModName

    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
            title = self.windowTitle() + ' ' + self.nameModule
            self.setWindowTitle(title)
        else:
            QDialog.changeEvent(self, event)



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
        QPushButton.__init__(self,  parent.argumentsContainer)
        self.targetResult = targetResult
        self.parent = parent
        self.vtype = vtype
        self.setObjectName("Button" + arg_name)
        self.setText(parent.browseButton.text())
        self.setFixedSize(QSize(80,  28))
        self.connect(self,  SIGNAL("clicked()"), self.click)
        
    def click(self):
        if self.vtype == 1:
            sFileName = QFileDialog.getOpenFileName(self, self.parent.browseButton.toolTip(),  "/home")
            if (sFileName):
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

