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
#  Solal Jacob <sja@arxsys.fr>
#  Jeremy MOUNIER <jmo@arxsys.fr>
# 

import os
import sys
from Queue import *

# Form Custom implementation of MAINWINDOW
from PyQt4.QtGui import QAction,  QApplication, QDockWidget, QFileDialog, QIcon, QMainWindow, QMessageBox, QMenu, QTabWidget, QTextEdit, QTabBar
from PyQt4.QtCore import QEvent, Qt,  SIGNAL, QModelIndex, QSettings, QFile, QString, QTimer
from PyQt4 import QtCore, QtGui

from api.type import *
from api.vfs.libvfs import *
from api.taskmanager import scheduler 

from api.gui.widget.textedit import TextEdit
from api.gui.widget.dockwidget import DockWidget 
from api.gui.dialog.property import Property
from api.gui.widget.nodebrowser import NodeBrowser
from api.gui.dialog.applymodule import ApplyModule

from ui.gui.configuration.configure import ConfigureDialog
from ui.gui.configuration.conf import Conf
from ui.gui.configuration.translator import Translator
from ui.gui.ide.actions import IdeActions

from ui.gui.widget.taskmanager import Processus
from ui.gui.widget.modules import Modules
from ui.gui.widget.env import Env
from ui.gui.widget.stdio import STDErr, STDOut

from ui.gui.widget.shell import ShellActions
from ui.gui.widget.interpreter import InterpreterActions

from ui.gui.utils.utils import Utils
from ui.gui.utils.menu import MenuTags
from ui.gui.dialog.dialog import Dialog

try:
    from ui.gui.widget.help import Help
 # Documentation
    try:
        from api.settings import DOC_PATH
    except:
        DOC_PATH = "./ui/gui/help.qhc"
        HELP = True
except ImportError:
    HELP = False


class MainWindow(QMainWindow):
    def __init__(self,  app, debug = False):
        super(MainWindow,  self).__init__()
        self.app = app
        self.debug = debug
        self.sched = scheduler.sched
        self.vfs = VFS.Get()

        self.dialog = Dialog(self)
	
	self.initCallback()
	#menu
	self.menuList = [[self.tr("File"), ["New_Dump", "New_Device", "Exit"]],
                         ["Modules", ["Load"]],
                         ["View", ["Maximize", "Fullscreen mode"]],
                         ] 

	#icon 
        self.toolbarList = [["New_Dump"],
                            ["New_Device"],
                            ["List_Files"],
                            ["Maximize"],
                            ["Fullscreen mode"]
                            ]
        if HELP:
            self.toolbarList.append(["help"])

        self.actionList = [
            ["New_Dump", self.tr("Open evidence file(s)"), self.dialog.addFiles, ":add_image.png", "Add image"],
            ["New_Device", self.tr("Open local device"), self.dialog.addDevices, ":add_device.png", "Add device(s)"],
            ["Maximize", self.tr("Maximize"), self.maximizeDockwidget,  ":maximize.png", "Maximize"],
            ["Fullscreen mode", self.tr("Fullscreen mode"), self.fullscreenMode,  ":randr.png", "Fullscreen mode"],
            ["Exit", self.tr("Exit"), None,  ":exit.png", "Exit"], 
            ["Load", self.tr("Load"), self.dialog.loadDriver, None, None ],
            ["About", "?", self.dialog.about, None, None ],
            ["List_Files", self.tr("List Files"), self.addNodeBrowser, ":view_detailed.png", "Open List"]
            ] 
        if HELP:
            self.actionList.append(["help", "Help", self.addHelpWidget, ":help.png", "Open Help"])

        self.setupUi()
        self.ideActions = IdeActions(self)
	self.shellActions = ShellActions(self)
	self.interpreterActions = InterpreterActions(self)
	self.addMenu(*[self.tr("About"), ["About"]])
        self.initDockWidgets()
        self.setCentralWidget(None)

        self.refreshTabifiedDockWidgets()

#############  DOCKWIDGETS FUNCTIONS ###############

    def addDockWidgets(self, widget, master=True):
        if widget is None:
            return
        dockwidget = DockWidget(self, widget, widget.name)
        name = self.getWidgetName(widget.name)
        dockwidget.setWindowTitle(name)
        self.connect(dockwidget, SIGNAL("resizeEvent"), widget.resize)

        self.addDockWidget(self.masterArea, dockwidget)
        if master:
            self.tabifyDockWidget(self.master, dockwidget)
        else:
            self.tabifyDockWidget(self.second, dockwidget)

        self.dockWidget[name] = dockwidget
        self.refreshTabifiedDockWidgets()

    def getWidgetName(self, name):
        did = 0
        for d in self.dockWidget:
            if d[:len(str(name))] == str(name):
                did += 1
        if did > 0:
            name = name + str(did)
        return name

    def addSingleDock(self, name, cl):
        try :
	   self.dockWidget[name].show()
        except KeyError:
            w = cl(self)
            self.addDockWidgets(w, master=False)
           
    def addNodeBrowser(self, rootpath=None):
        if rootpath == None:
            self.addDockWidgets(NodeBrowser(self)) 
        else:
            nb = NodeBrowser(self)
            nb.model.setRootPath(nb.vfs.getnode(rootpath))
            self.addDockWidgets(nb)

    def addHelpWidget(self):
        path = DOC_PATH
        file = QFile(path)
        if not file.exists(path):
            if DOC_PATH:
                dialog = QMessageBox.warning(self, "Error while loading help", QString(str(DOC_PATH) + ": No such file.<br>You can check on-line help at <a href=\"http://wiki.digital-forensic.org/\">http://wiki.digital-forensic.org</a>."))
            else:
                dialog = QMessageBox.warning(self, "Error while loading help", QString("Documentation path not found.<br>You can check on-line help at <a href=\"http://wiki.digital-forensic.org/\">http://wiki.digital-forensic.org</a>."))
            return

        self.addDockWidgets(Help(self, path=path))

    def addInterpreter(self):
       self.addSingleDock("Interpreter", Interpreter)
 
    def initDockWidgets(self):
        """Init Dock in application and init DockWidgets"""
        widgetPos = [ ( Qt.TopLeftCorner, Qt.LeftDockWidgetArea, QTabWidget.North),
	 (Qt.BottomLeftCorner, Qt.BottomDockWidgetArea, QTabWidget.South), 
	 (Qt.TopLeftCorner, Qt.TopDockWidgetArea, QTabWidget.North), 
	 (Qt.BottomRightCorner, Qt.RightDockWidgetArea, QTabWidget.North) ]

        for corner, area, point in widgetPos:
            self.setCorner(corner, area)
            try:
                self.setTabPosition(area, point)
            except AttributeError:
                pass
        self.dockWidget = {}
        self.widget = {}
        self.masterArea = Qt.TopDockWidgetArea
        self.secondArea = Qt.BottomDockWidgetArea
        self.last_state = None
        self.last_dockwidget = None
        self.last_widget = None

        self.createFirstWidgets()

    def createFirstWidgets(self):
	self.nodeBrowser = NodeBrowser(self)
        self.master = DockWidget(self, self.nodeBrowser, self.nodeBrowser.name)
        self.master.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.master.setWindowTitle("nodebrowser")
        self.dockWidget["nodebrowser"] = self.master
        self.wprocessus = Processus(self)
        self.second = DockWidget(self, self.wprocessus, "Task manager")
        self.second.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.second.setWindowTitle("Task manager")
        self.dockWidget["Task manager"] = self.second
        self.addDockWidget(self.masterArea, self.master)
        self.addDockWidget(self.secondArea, self.second)

        self.timer = QTimer(self)
	self.connect(self.timer, SIGNAL("timeout()"), self.refreshSecondWidgets)
        self.timer.start(2000)      

        self.wstdout = STDOut(self, self.debug)
        self.wstderr = STDErr(self, self.debug)

        self.addDockWidgets(self.wstdout, master=False)
        self.addDockWidgets(self.wstderr, master=False)
        self.wmodules = Modules(self)
        self.addDockWidgets(self.wmodules, master=False)
        self.wenv = Env(self)
        self.addDockWidgets(self.wenv, master=False)
        self.refreshSecondWidgets()
        self.refreshTabifiedDockWidgets()

    def maximizeDockwidget(self):
        if self.last_state is None:
            self.last_state = self.saveState()
            focus_widget = QApplication.focusWidget()
            for key, dock in self.dockWidget.iteritems():
                dock.hide()
                if dock.isAncestorOf(focus_widget):
                    self.last_dockwidget = dock
            self.last_widget = self.last_dockwidget.widget()
            self.last_dockwidget.toggleViewAction().setDisabled(True)
            self.setCentralWidget(self.last_dockwidget.widget())
            self.last_dockwidget.visibility_changed(True)
        else:
            self.last_dockwidget.setWidget(self.last_widget)
            self.last_dockwidget.toggleViewAction().setEnabled(True)
            self.setCentralWidget(None)
            self.restoreState(self.last_state)
            self.last_dockwidget.setFocus()
            self.last_state = None
            self.last_widget = None
            self.last_dockwidget = None

    def fullscreenMode(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def refreshSecondWidgets(self):
	self.wprocessus.LoadInfoProcess()
        self.wmodules.LoadInfoModules()
	self.wenv.LoadInfoEnv()        

    def refreshTabifiedDockWidgets(self):
        allTabs = self.findChildren(QTabBar)
        for tabGroup in allTabs:
            for i in range(tabGroup.count()):
                for v in self.dockWidget.values():
                    title = str(tabGroup.tabText(i))
                    if title.startswith(v.windowTitle()) and not v.widget().windowIcon().isNull():
                        tabGroup.setTabIcon(i, v.widget().windowIcon()) 

#############  END OF DOCKWIDGETS FUNCTIONS ###############

    def applyModule(self, modname, modtype, selected):
        appMod = ApplyModule(self)
        appMod.openApplyModule(modname, modtype, selected)

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

    def addToolBars(self, toolbar):
        """ Init Toolbar"""
        for action in toolbar:
           self.toolBarMain.addAction(self.action[action])

    def addMenu(self, name, actionList = None):
        self.menu[name] = QMenu(self.menubar)
        self.menu[name].setObjectName(name)
        self.menu[name].setTitle(name)
        if actionList:
          for action in actionList:
            self.menu[name].addAction(self.action[action])
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
        self.setupAction(self.actionList)
	self.setupMenu(self.menuList)    
 
        self.MenuTags = MenuTags(self, self)
        QtCore.QObject.connect(self.action["Exit"],QtCore.SIGNAL("triggered()"),self.close)
        QtCore.QMetaObject.connectSlotsByName(self)

        self.setupStatusBar()
 
        self.toolBarMain = QtGui.QToolBar(self)
        self.toolBarMain.setWindowTitle("toolBar")
        self.toolBarMain.setObjectName("toolBar")
        self.addToolBar(QtCore.Qt.TopToolBarArea,self.toolBarMain)
        for toolbar in self.toolbarList:
	   self.addToolBars(toolbar)
 

