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
#  Francois Percot <percot@gmail.com>
# 

import os
from Queue import *

# Form Custom implementation of MAINWINDOW
from PyQt4.QtGui import QAction,  QApplication, QDockWidget, QFileDialog, QIcon, QMainWindow, QMessageBox, QMenu, QTabWidget
from PyQt4.QtCore import QEvent, Qt,  SIGNAL, QModelIndex, QSettings
from PyQt4 import QtCore, QtGui

from api.type import *
from api.vfs.libvfs import *
from api.taskmanager import scheduler 

from api.gui.dialog.selectnodes import SelectNodes
from api.gui.dialog.applymodule import ApplyModule
from api.gui.widget.nodetree import NodeTree
from api.gui.widget.textedit import TextEdit
from api.gui.widget.dockwidget import DockWidget 
from api.gui.dialog.property import Property

from ui.gui.configuration.configure import ConfigureDialog
from ui.gui.configuration.conf import Conf
from ui.gui.configuration.translator import Translator
from ui.gui.ide.ide import Ide
from ui.gui.ide.actions import IdeActions
from ui.gui.widget.info import Info
from ui.gui.widget.shell import Shell
from ui.gui.widget.interpreter import Interpreter
from ui.gui.widget.stdio import IO
from ui.gui.utils.utils import Utils
from ui.gui.utils.menu import MenuTags
from ui.gui.dialog.dialog import Dialog

class MainWindow(QMainWindow):
    def __init__(self,  app):
        super(MainWindow,  self).__init__()
        self.app = app
        self.sched = scheduler.sched
        self.vfs = VFS.Get()

        self.ApplyModule = ApplyModule(self)
        self.PropertyDialog = Property(self)
        self.SelectNodes = SelectNodes(self)
        self.dialog = Dialog(self)
	
	self.initCallback()
        self.initDockWidgets()

        self.menuList = [
	     ["File", [ ["New_Dump", "Add Dump", self.dialog.addDumps, ":add.png", "Add Dump"],
		        ["Exit", "Exit", None,  ":exit.png", "Exit"] ], ],
	     ["Modules", [ ["Load", "Load", self.dialog.loadDriver ] ], ],
	     ["About",   [ ["About", "?", self.dialog.about ] ],  ],
	  ] 

        self.actionList = [ 
	     ["ApplyModule", "ApplyModule", self.ApplyModule.openApplyModule, ":exec.png", "Open With"],
	     ["Shell", "Shell",  self.addShell, ":shell.png", "Open Shell"],
             ["Interpreter", "Interpreter", self.addInterpreter, ":interpreter.png", "Open Interpreter"],
	     ["List_Files", "List Files", self.widget["NodeTree"].addList, ":list.png", "Open List"]
	  ] 

        self.toolbarList = [
             ["New_Dump"],
	     ["ApplyModule", "Shell", "Interpreter", "List_Files"]
	]

        self.setupUi()
        self.readSettings()
       
    def initCallback(self):
        self.sched.set_callback("add_qwidget", self.qwidgetResult)
        self.connect(self, SIGNAL("qwidgetResultView"), self.qwidgetResultView)

    def qwidgetResult(self, qwidget):
        self.emit(SIGNAL("qwidgetResultView"), qwidget)
 
    def strResult(self, proc):
        self.emit(SIGNAL("strResultView"), proc)
           
    def qwidgetResultView(self, proc):
	try :
           proc.inst.g_display()
           self.addDockWidgets(proc.inst)
	except :
	   trace = sys.exc_info()
	   proc.error(trace)
        proc.inst.updateWidget()
	proc.error() 

    def strResultView(self, proc):
   	widget = TextEdit(proc)
	try :
	   res = ''
	   txt = proc.stream.get(0)
	   res += txt	
	   while txt:
	      txt = proc.stream.get(0)   
	      res += txt
	except Empty:
	    pass   
	if res and res != '':
	   widget.emit(SIGNAL("puttext"), res)
           self.addDockWidgets(widget)

    def addShell(self):
       self.addSingleDock("Shell", Shell)
      
    def addInterpreter(self):
       self.addSingleDock("Interpreter", Interpreter)	
 
    def addSingleDock(self, name, cl):
        try :
	   self.dockWidget[name].show()
        except KeyError:
           self.dockWidget[name] = cl(self)
           self.addNewDockWidgetTab(Qt.RightDockWidgetArea, self.dockWidget[name])

    def addDock(self, name, cl):
           self.dockWidget[name] = cl(self)
           self.addNewDockWidgetTab(Qt.BottomDockWidgetArea, self.dockWidget[name])

    def addDockWidgets(self, widget):
        dockwidget = DockWidget(self, widget, widget.name)
        self.connect(dockwidget, SIGNAL("resizeEvent"), widget.resize)
        self.addNewDockWidgetTab(Qt.RightDockWidgetArea, dockwidget)
  
    def initDockWidgets(self):
        """Init Dock in application and init DockWidgets"""
        widgetPos = [ ( Qt.TopLeftCorner, Qt.LeftDockWidgetArea, QTabWidget.North),
	 (Qt.BottomLeftCorner, Qt.BottomDockWidgetArea, QTabWidget.North), 
	 (Qt.BottomRightCorner, Qt.RightDockWidgetArea, QTabWidget.North) ]

        for corner, area, point in widgetPos:
	   self.setCorner(corner, area)
           try:
               self.setTabPosition(area, point)
           except AttributeError:
               pass
               
        self.dockWidget = {}
        self.widget = {}
      
        self.addDock("IO", IO)
        self.addDock("Info", Info) 
 
        self.widget["NodeTree"] = NodeTree(self).instance
        self.setCentralWidget(self.widget["NodeTree"])
        dock = self.widget["NodeTree"].addList()
        self.widget["NodeTree"].setChild(dock.widget)
 
    def addNewDockWidgetTab(self, dockArea, dockWidget):
        if dockWidget is None :
            return
#XXX api/gui/widget/nodetree -> rajoute la dockwidget rightdock \ ["list"] a modifier
        for dock in self.dockWidget.itervalues():
           if self.dockWidgetArea(dock) == dockArea:
             self.addDockWidget(dockArea, dockWidget)
             self.tabifyDockWidget(dock, dockWidget)
             return

        self.addDockWidget(dockArea, dockWidget)
    
    def addResultatDockWidget(self, dockWidget):
        if self.widget["NodeTree"] is None :
            self.widget["NodeTree"] = dockWidget
 
    def addToolBars(self, toolbar):
        """ Init Toolbar"""
        for action in toolbar:
           self.toolBarMain.addAction(self.action[action])
        self.toolBarMain.addSeparator()

    def addMenu(self, name, actionList = None):
        self.menu[name] = QMenu(self.menubar)
        self.menu[name].setObjectName(name)
        self.menu[name].setTitle(name)
        if actionList:
          for action in actionList:
            self.addAction(*action)
            self.menu[name].addAction(self.action[action[0]])
#if suivant si non pas mettre de separator si pas d autre action
            self.menu[name].addSeparator()
            self.menubar.addAction(self.menu[name].menuAction())

    def setupMenu(self, menuList):
        self.menubar = QtGui.QMenuBar(self)
        self.menubar.setGeometry(QtCore.QRect(0,0,1014,32))
        self.menubar.setDefaultUp(False)
        self.menubar.setObjectName("menubar")
        self.setMenuBar(self.menubar)

        for menu in menuList:
          self.addMenu(*menu) 
          
    def addAction(self, name, text, func = None, iconName = None, iconText = None):
        self.action[name] = QtGui.QAction(self)
        self.action[name].setObjectName("action" + name)
        self.action[name].setText(text)
        if iconName:
          self.action[name].setIcon(QIcon(iconName))
          if iconText:
            self.action[name].setIconText(iconText)
        if func:
          self.connect(self.action[name], SIGNAL("triggered()"), func)

    def setupAction(self, actionList):
        for action in actionList:
          self.addAction(*action)
        self.actionTools = QtGui.QAction(self)
        self.actionTools.setCheckable(True)
        self.actionTools.setChecked(True)
        self.actionTools.setObjectName("actionTools")
        self.ideActions = IdeActions(self, None)
        self.menubar.addAction(self.ideActions.menu.menuAction())
    
    def setupFont(self):
        font = QtGui.QFont()
        font.setFamily("Metal")
        font.setWeight(70)
        font.setBold(False)
        self.setFont(font)

    def setupStatusBar(self):
        self.statusbar = QtGui.QStatusBar(self)
        self.statusbar.setSizeGripEnabled(False)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)
 
    def setupUi(self):
        self.menu = {}          
        self.action = {}
        self.setObjectName("MainWindow")
        self.setWindowModality(QtCore.Qt.ApplicationModal)
        self.resize(QtCore.QSize(QtCore.QRect(0,0,1014,693).size()).expandedTo(self.minimumSizeHint()))
        self.setWindowTitle("Digital Forensics Framework ")
      
        self.setupFont()
 
        self.setAnimated(True)
        self.setDockNestingEnabled(True)
        self.setDockOptions(QtGui.QMainWindow.AllowNestedDocks|QtGui.QMainWindow.AllowTabbedDocks|QtGui.QMainWindow.AnimatedDocks)
        self.setUnifiedTitleAndToolBarOnMac(False)
	self.setupMenu(self.menuList)    
        self.setupAction(self.actionList)
 
        self.MenuTags = MenuTags(self, self)
        QtCore.QObject.connect(self.action["Exit"],QtCore.SIGNAL("triggered()"),self.close)
        QtCore.QMetaObject.connectSlotsByName(self)

        self.setupStatusBar()
 
        self.toolBarMain = QtGui.QToolBar(self)
        self.toolBarMain.setWindowTitle("toolBar")
        self.addToolBar(QtCore.Qt.TopToolBarArea,self.toolBarMain)
        for toolbar in self.toolbarList:
	   self.addToolBars(toolbar)
        self.addToolBar(Qt.TopToolBarArea, self.ideActions.maintoolbar)
 
    def closeEvent(self, e):
        settings = QSettings("ArxSys", "DFF-0.5")
	settings.setValue("geometry", self.saveGeometry())
	settings.setValue("windowState", self.saveState())

    def readSettings(self):
        return	
	settings = QSettings("ArxSys", "DFF-0.5")
	self.restoreGeometry(settings.value("geometry").toByteArray())
	self.restoreState(settings.value("windowState").toByteArray())
