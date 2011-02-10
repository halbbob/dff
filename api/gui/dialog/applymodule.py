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
import traceback

from PyQt4.QtGui import QAbstractItemView, QApplication, QCheckBox, QDialog, QGridLayout, QLabel, QMessageBox,QSplitter, QVBoxLayout, QWidget, QDialogButtonBox, QPushButton, QLineEdit, QCompleter, QSortFilterProxyModel, QGroupBox, QFileDialog, QSpinBox, QFormLayout, QHBoxLayout, QStackedWidget, QListWidget, QListWidgetItem, QTextEdit, QPalette, QComboBox, QIntValidator
from PyQt4.QtCore import Qt,  QObject, QRect, QSize, SIGNAL, QModelIndex, QString, QEvent
# CORE
from api.loader import *
from api.vfs import *
from api.taskmanager.taskmanager import *
from api.types.libtypes import Argument, Parameter, Variant, VMap, VList, typeId

from api.gui.model.vfsitemmodel import  VFSItemModel
from api.gui.widget.nodeview import NodeTreeView

from api.gui.box.checkbox import checkBoxWidget
from ui.gui.resources.ui_applymodule import Ui_applyModule 

from ui.gui.utils.utils import Utils

from api.gui.widget.layoutmanager import *


class ApplyModule(QDialog, Ui_applyModule):
    def __init__(self,  mainWindow):
        super(QDialog, self).__init__()
        self.setupUi(self)
        self.labActivate.setVisible(False)
        self.labType.setVisible(False)
        self.labDescription.setVisible(False)
        p = self.modulepix.pixmap().scaled(64,64, Qt.KeepAspectRatio)
        self.modulepix.setPixmap(p)
        self.connect(self.buttonBox,SIGNAL("accepted()"), self.validateModule)
        self.__mainWindow = mainWindow
        self.loader = loader.loader()
        self.vfs = vfs.vfs()
        self.valueArgs = {}
    
    def initAllInformations(self, nameModule, typeModule, nodesSelected):
        self.__nodesSelected = nodesSelected
        self.nameModule = nameModule
        title = self.windowTitle() + ' ' + str(nameModule)
        self.setWindowTitle(title)
        self.nameModuleField.setText(nameModule)
        self.typeModuleField.setText(typeModule)

        self.conf = self.loader.get_conf(str(nameModule))
        self.textEdit.setText(self.conf.description)

        args = self.conf.arguments()
        self.createArgShape(args)
    
    def createArgShape(self, args):
        self.connect(self.listargs, SIGNAL("currentItemChanged(QListWidgetItem*,QListWidgetItem*)"), self.argChanged)
        for arg in args:
            self.createArgument(arg)

        self.listargs.item(0).setSelected(True)
        self.argsLayout.setStretchFactor(0, 1)
        self.argsLayout.setStretchFactor(1, 3)

    def createArgument(self, arg):
        warg = QWidget()
        vlayout = QVBoxLayout()
        vlayout.setSpacing(5)
        vlayout.setMargin(0)
        winfo = QWidget()
        infolayout = QFormLayout()
        infolayout.setMargin(0)
        requirement = arg.requirementType()
        # Generate argument's widget
        warguments = self.getWidgetFromType(arg)

        if arg.requirementType() in (Argument.Optional, Argument.Empty):
            checkBox =  checkBoxWidget(self, winfo, warguments, self.labActivate.text())
            vlayout.addWidget(checkBox, 0)

        infolayout.addRow(self.labType.text(), QLabel(str(typeId.Get().typeToName(arg.type()))))
        tedit = QTextEdit(str(arg.description()))
        tedit.setReadOnly(True)
        infolayout.addRow(tedit)
        winfo.setLayout(infolayout)
        vlayout.addWidget(winfo, 1)
        if warguments:
            vlayout.addWidget(warguments, 2)        
            self.valueArgs[arg.name()] = warguments
        self.stackedargs.addWidget(warg)
        warg.setLayout(vlayout)
        argitem = QListWidgetItem(str(arg.name()), self.listargs)

    def getWidgetFromType(self, arg):
        warguments = layoutManager()
        inputype = arg.inputType()
        predefs = arg.parameters()
        ptype = arg.parametersType()
        if ptype == Parameter.Editable:
            editable = True
        else:
            editable = False
        if inputype == Argument.Single:
            if arg.type() in (typeId.Node, typeId.Path):
                warguments.addPath(arg.name(), arg.type(), predefs, editable)
            else:
                warguments.addSingleArgument(arg.name(), predefs, editable)
        elif inputype == Argument.List:
            if arg.type() in (typeId.Node, typeId.Path):
                warguments.addPathList(arg.name(), arg.type(), predefs)
            else:
                warguments.addListArgument(arg.name(), arg.type(), predefs, editable)
        else:
            # Argument.Empty (typically, bool arguments)
            return None
        return warguments

    def validateModule(self):
        # get values
        args = {}
        for argname, lmanager in self.valueArgs.iteritems():
#            print "Argname ", argname
#            print "value(s)", lmanager.get(argname)
#            print lmanager.isEnabled()
            if lmanager.isEnabled():
                print "Enter ", argname
                args[argname] = lmanager.get(argname)
        try : 
            self.conf.generate(args)
        except RuntimeError:
            (filename, line_number, function_name, text) = traceback.extract_tb()
            print "conf pas bonne"

#########
#            if not i.optional :
#                if i.type == "node" :
#                    node = self.vfs.getnode(str(self.valueArgs[i].text()))
                    #node = self.valueArgs[i].currentNode()"
#                    if node is None :
#                        errorArg.append(i)
#                else :
#                    if i.type != "int":
#                        value = str(self.valueArgs[i].currentText())
#                        if value == "" :
#                            errorArg.append(i)
#                    else:
#                        v = self.valueArgs[i].currentText().toInt()
#                        value = v[0]
#        if len(errorArg) > 0:
#            # Create a dialog with QT designer
#            print "Module error"
#        else:
#            self.accept()
#############

    def getArguments(self):
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
        self.taskmanager.add(str(self.nameModule), self.arg, ["thread", "gui"])
        return

    def openApplyModule(self, nameModule = None, typeModule = None, nodesSelected = None):
        self.initAllInformations(nameModule, typeModule, nodesSelected)
        iReturn = self.exec_()
        if iReturn:
            arg = self.getArguments()

    def argChanged(self, curitem, previtem):
        self.stackedargs.setCurrentIndex(self.listargs.row(curitem))

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

