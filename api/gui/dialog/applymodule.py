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
import sys

from PyQt4.QtGui import QAbstractItemView, QApplication, QCheckBox, QDialog, QGridLayout, QLabel, QMessageBox,QSplitter, QVBoxLayout, QWidget, QDialogButtonBox, QPushButton, QLineEdit, QCompleter, QSortFilterProxyModel, QGroupBox, QFileDialog, QSpinBox, QFormLayout, QHBoxLayout, QStackedWidget, QListWidget, QListWidgetItem, QTextEdit, QPalette, QComboBox, QIntValidator
from PyQt4.QtCore import Qt,  QObject, QRect, QSize, SIGNAL, QModelIndex, QString, QEvent

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
        QDialog.__init__(self, mainWindow)
        Ui_applyModule.__init__(self)
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

        self.translation()
    
    def initAllInformations(self, nameModule, typeModule, nodesSelected):
        self.__nodesSelected = nodesSelected
        self.nameModule = nameModule
        title = self.windowTitle() + ' ' + str(nameModule)
        self.setWindowTitle(title)
        self.nameModuleField.setText(nameModule)
        self.typeModuleField.setText(typeModule)

        self.conf = self.loader.get_conf(str(nameModule))
        try:
            self.textEdit.setText(self.conf.description)
        except TypeError:
            self.textEdit.setText(self.conf.description())
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
                warguments.addSingleArgument(arg.name(), predefs, arg.type(), editable)
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
        try :
            for argname, lmanager in self.valueArgs.iteritems():
                if lmanager.isEnabled():
                    arg = self.conf.argumentByName(argname)
                    if arg.type() == typeId.Node and arg.inputType() == Argument.List:
                        plist = lmanager.get(argname)
                        params = []
                        for param in plist:
                            params.append(self.vfs.getnode(param))
                    elif arg.type() == typeId.Node and arg.inputType() == Argument.Single:
                        params = self.vfs.getnode(lmanager.get(argname))
                    elif arg.inputType() == Argument.Empty:
                        params = True
                    else:                        
                        params = lmanager.get(argname)
                    args[argname] = params
            genargs = self.conf.generate(args)
            self.taskmanager = TaskManager()
            self.taskmanager.add(str(self.nameModule), genargs, ["thread", "gui"])
            self.accept()
        except RuntimeError:
            err_type, err_value, err_traceback = sys.exc_info()
            err_trace =  traceback.format_tb(err_traceback)
            err_typeval = traceback.format_exception_only(err_type, err_value)
            terr = QString()
            detailerr = QString()
            for err in err_trace:
                detailerr.append(err)
            for errw in err_typeval:
                terr.append(errw)
                detailerr.append(err)
            self.messageBox(terr, detailerr)
        return

    def openApplyModule(self, nameModule = None, typeModule = None, nodesSelected = None):
        self.initAllInformations(nameModule, typeModule, nodesSelected)
        self.exec_()

    def argChanged(self, curitem, previtem):
        self.stackedargs.setCurrentIndex(self.listargs.row(curitem))

    def messageBox(self, coretxt, detail):
        msg = QMessageBox(self)
        msg.setWindowTitle(self.configureError)
        msg.setText(self.configureErrorMsg)
        msg.setInformativeText(coretxt)
        msg.setIcon(QMessageBox.Critical)
        msg.setDetailedText(detail)
        msg.setStandardButtons(QMessageBox.Ok)
        ret = msg.exec_()

    def translation(self):
        self.configureError = self.tr("Configuration error")
        self.configureErrorMsg = self.tr("An error was detected in the configuration")

    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
            title = self.windowTitle() + ' ' + self.nameModule
            self.setWindowTitle(title)
            self.translation()
        else:
            QDialog.changeEvent(self, event)

