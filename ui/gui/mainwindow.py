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
from ui.gui.resources.ui_mainwindow import Ui_MainWindow

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


class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self,  app, debug = False):
        super(MainWindow,  self).__init__()
        self.app = app
        self.debug = debug
        self.sched = scheduler.sched
        self.vfs = VFS.Get()

        self.dialog = Dialog(self)
	
	self.initCallback()

        if HELP:
            self.toolbarList.append(["help"])
        if HELP:
            self.actionList.append(["help", "Help", self.addHelpWidget, ":help.png", "Open Help"])

        # Set up the user interface from Qt Designer
        self.setupUi(self)

        # Customization
        self.setWindowModality(QtCore.Qt.ApplicationModal)
        self.resize(QtCore.QSize(QtCore.QRect(0,0,1014,693).size()).expandedTo(self.minimumSizeHint()))


	self.shellActions = ShellActions(self)

        self.ideActions = IdeActions(self)

	self.interpreterActions = InterpreterActions(self)
        self.initDockWidgets()
        self.setCentralWidget(None)

        # Signals handling
        ## File menu
        self.connect(self.actionOpen_evidence, SIGNAL("triggered()"), self.dialog.addFiles)
        self.connect(self.actionOpen_device, SIGNAL("triggered()"), self.dialog.addDevices)
        self.connect(self.actionExit, SIGNAL("triggered()"), self.close)
        ## Edit menu
        self.connect(self.actionPreferences, SIGNAL("triggered()"), self.dialog.preferences)
        ## Module menu
        self.connect(self.actionLoadModule, SIGNAL("triggered()"), self.dialog.loadDriver)
        ## View menu
        self.connect(self.actionMaximize, SIGNAL("triggered()"), self.maximizeDockwidget)
        self.connect(self.actionFullscreen_mode, SIGNAL("triggered()"), self.fullscreenMode)
        self.connect(self.actionNodeBrowser, SIGNAL("triggered()"), self.addNodeBrowser)
        self.connect(self.actionShell, SIGNAL("triggered()"), self.shellActions.create)
# Interpreter ?        self.connect(, SIGNAL("triggered()"), self.)
        ## About menu
        self.connect(self.actionHelp, SIGNAL("triggered()"), self.addHelpWidget)
        self.connect(self.actionAbout, SIGNAL("triggered()"), self.dialog.about)

        
        self.toolbarList = [[self.actionOpen_evidence],
                            [self.actionOpen_device],
                            [self.actionNodeBrowser],
                            [self.actionMaximize],
                            [self.actionFullscreen_mode],
                            [self.actionShell],
                            [self.actionPython_interpreter],
                            [self.actionHelp]
                            ]

        # Set up toolbar
        self.setupToolBar()

        # Set up modules menu
        self.MenuTags = MenuTags(self, self)

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
            if d[:QString(name).length()] == QString(name):
                did += 1
        if did > 0:
            name = name + ' ' + str(did)
        return name

    def addSingleDock(self, name, cl):
        print 'adding', name
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
	 (Qt.BottomLeftCorner, Qt.BottomDockWidgetArea, QTabWidget.North), 
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
            self.refreshTabifiedDockWidgets()

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
                    if tabGroup.tabText(i).startsWith(v.windowTitle()) and not v.widget().windowIcon().isNull():
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
           self.toolBar.addAction(action)

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

    def setupToolBar(self):
        for toolbar in self.toolbarList:
	   self.addToolBars(toolbar)

    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
        else:
            QMainWindow.changeEvent(self, event)
