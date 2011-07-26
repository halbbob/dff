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
from PyQt4.QtGui import QAction,  QApplication, QDockWidget, QFileDialog, QIcon, QMainWindow, QMessageBox, QMenu, QTabWidget, QTextEdit, QTabBar, QPushButton, QCheckBox, QHBoxLayout, QVBoxLayout, QWidget
from PyQt4.QtCore import QEvent, Qt,  SIGNAL, QModelIndex, QSettings, QFile, QString, QTimer
from PyQt4 import QtCore, QtGui

from api.vfs.libvfs import *
from api.taskmanager import scheduler
from api.vfs import vfs

from api.gui.widget.textedit import TextEdit
from api.gui.widget.dockwidget import DockWidget 
from api.gui.widget.nodebrowser import NodeBrowser
from api.gui.dialog.applymodule import ApplyModule

from ui.conf import Conf
from ui.gui.translator import Translator
from ui.gui.ide.ide import Ide

from ui.gui.widget.taskmanager import Processus
from ui.gui.widget.modules import Modules
from ui.gui.widget.stdio import STDErr, STDOut
from ui.gui.widget.shell import ShellActions
from ui.gui.widget.interpreter import InterpreterActions
from ui.gui.widget.preview import Preview

from ui.gui.utils.utils import Utils
from ui.gui.utils.menu import MenuTags
from ui.gui.dialog.dialog import Dialog
from ui.gui.resources.ui_mainwindow import Ui_MainWindow

# Documentation
from ui.gui.widget.help import Help

class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self,  app, debug = False):
        super(MainWindow,  self).__init__()
        self.app = app
        self.debug = debug
        self.sched = scheduler.sched
#        self.vfs = VFS.Get()
        self.vfs = vfs.vfs()
        self.createRootNodes()

        self.dialog = Dialog(self)
	
	self.initCallback()


        # Set up the user interface from Qt Designer
        self.setupUi(self)
        self.translation()

        # Customization
        self.setWindowModality(QtCore.Qt.ApplicationModal)
        self.resize(QtCore.QSize(QtCore.QRect(0,0,1014,693).size()).expandedTo(self.minimumSizeHint()))

	self.shellActions = ShellActions(self)
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
        ## Ide menu
        self.connect(self.actionIdeOpen, SIGNAL("triggered()"), self.addIde)        
        ## View menu
        self.connect(self.actionMaximize, SIGNAL("triggered()"), self.maximizeDockwidget)
        self.connect(self.actionFullscreen_mode, SIGNAL("triggered()"), self.fullscreenMode)
        self.connect(self.actionNodeBrowser, SIGNAL("triggered()"), self.addNodeBrowser)
        self.connect(self.actionShell, SIGNAL("triggered()"), self.shellActions.create)
        self.connect(self.actionPython_interpreter, SIGNAL("triggered()"), self.interpreterActions.create)        ## About menu
        self.connect(self.actionHelp, SIGNAL("triggered()"), self.addHelpWidget)
        self.connect(self.actionAbout, SIGNAL("triggered()"), self.dialog.about)

        # list used to build toolbar
        # None will be a separator
        self.toolbarList = [self.actionOpen_evidence,
                            self.actionOpen_device,
                            None,
                            self.actionNodeBrowser,
                            self.actionShell,
                            self.actionPython_interpreter,
                            self.actionIdeOpen,
                            self.actionHelp,
                            None,
                            self.actionMaximize,
                            self.actionFullscreen_mode,
                            ]

        # Set up toolbar
        self.setupToolBar()

        # Set up modules menu
        self.MenuTags = MenuTags(self, self)

        self.refreshTabifiedDockWidgets()
        
#############  DOCKWIDGETS FUNCTIONS ###############

    def addDockWidgets(self, widget, internalName, master=True):
        if widget is None:
            return
        if self.last_state is not None:
            self.maximizeDockwidget()
        dockwidget = DockWidget(self, widget, widget.name)
        docIndex, docTitle = self.getWidgetName(widget.name)
        dockwidget.setWindowTitle(QString.fromUtf8(docTitle))
        self.connect(dockwidget, SIGNAL("resizeEvent"), widget.resize)

        self.addDockWidget(self.masterArea, dockwidget)
        if master:
            self.tabifyDockWidget(self.master, dockwidget)
        else:
            self.tabifyDockWidget(self.second, dockwidget)

        if docIndex:
            self.dockWidget[internalName + str(docIndex)] = dockwidget
        else:
            self.dockWidget[internalName] = dockwidget
        self.refreshTabifiedDockWidgets()

    def getWidgetName(self, name):
        did = 0
        for d in self.dockWidget:
            if self.dockWidget[d].windowTitle().startsWith(QString(name)):
                did += 1
        if did > 0:
            name = name + ' ' + str(did)
        return (did, name)

    def addSingleDock(self, name, cl, master=False):
        try:
            self.dockWidget[name].show()
            self.refreshTabifiedDockWidgets()
        except KeyError:
            w = cl(self)
            self.addDockWidgets(w, name, master)
           
    def addNodeBrowser(self, rootpath=None):
        if rootpath == None:
            self.addDockWidgets(NodeBrowser(self), 'nodeBrowser')
        else:
            nb = NodeBrowser(self)
	    if type(rootpath) == type(''):
	         nb.model.setRootPath(nb.vfs.getnode(rootpath))
	    else:
	         nb.model.setRootPath(rootpath)
            self.addDockWidgets(nb, 'nodeBrowser')

    def addSearchTab(self, search):
        self.addDockWidgets(search, 'Searchr')

    def addHelpWidget(self):
        conf = Conf()
        path = conf.docPath
        file = QFile(path)
        if not file.exists(path):
            if path:
                dialog = QMessageBox.warning(self, self.errorLoadingHelp, QString(path) + ": " + self.notAnHelpFile)
            else:
                dialog = QMessageBox.warning(self, self.errorLoadingHelp, self.noSuchHelpFile)
            return                
        self.addDockWidgets(Help(self, path=path), 'help')

    def addInterpreter(self):
       self.addSingleDock("Interpreter", Interpreter)

    def addIde(self):
       self.addSingleDock("IDE", Ide, master=True)
 
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
        self.master.setWindowTitle(self.nodeBrowser.windowTitle())
        self.dockWidget["nodebrowser"] = self.master
        self.wprocessus = Processus(self)
        self.second = DockWidget(self, self.wprocessus, "Task manager")
        self.second.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.second.setWindowTitle(self.wprocessus.windowTitle())
        self.dockWidget["Task manager"] = self.second
        self.addDockWidget(self.masterArea, self.master)
        self.addDockWidget(self.secondArea, self.second)

        self.timer = QTimer(self)
	self.connect(self.timer, SIGNAL("timeout()"), self.refreshSecondWidgets)
        self.timer.start(2000)      

        self.wstdout = STDOut(self, self.debug)
        self.wstderr = STDErr(self, self.debug)

        self.addDockWidgets(self.wstdout, 'stdout', master=False)
        self.addDockWidgets(self.wstderr, 'stderr', master=False)
        self.wmodules = Modules(self)
        self.addDockWidgets(self.wmodules, 'modules', master=False)
   
	self.preview = Preview(self)
        self.addDockWidgets(self.preview, 'preview', master=False)
 	self.connect(self, SIGNAL("previewUpdate"), self.preview.update)
  
	pinButton = QCheckBox()	
	pinButton.setChecked(True)
        pinButton.connect(pinButton, SIGNAL("stateChanged(int)"), self.preview.setUpdate)
	voidWidget = QWidget(self.dockWidget["preview"])
	vlayout = QVBoxLayout()
	vlayout.insertSpacing(0, -10)
	hlayout = QHBoxLayout()
	hlayout.insertSpacing(0, -5)
	vlayout.addLayout(hlayout)
	hlayout.addWidget(pinButton)
	voidWidget.setLayout(vlayout)

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
            if self.last_dockwidget != None:
                self.last_widget = self.last_dockwidget.widget()
                self.last_dockwidget.toggleViewAction().setDisabled(True)
                self.setCentralWidget(self.last_dockwidget.widget())
                self.last_dockwidget.visibility_changed(True)
                self.actionNodeBrowser.setEnabled(False)
                self.actionShell.setEnabled(False)
                self.actionPython_interpreter.setEnabled(False)
                self.actionIdeOpen.setEnabled(False)
                self.actionHelp.setEnabled(False)
            else:
                self.last_state = None
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
            self.actionNodeBrowser.setEnabled(True)
            self.actionShell.setEnabled(True)
            self.actionPython_interpreter.setEnabled(True)
            self.actionIdeOpen.setEnabled(True)
            self.actionHelp.setEnabled(True)

    def fullscreenMode(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def refreshSecondWidgets(self):
	self.wprocessus.LoadInfoProcess()
        self.wmodules.LoadInfoModules()


    def refreshTabifiedDockWidgets(self):
        allTabs = self.findChildren(QTabBar)
        for tabGroup in allTabs:
            for i in range(tabGroup.count()):
                for v in self.dockWidget.values():
                    if v.widget() and tabGroup.tabText(i).startsWith(v.windowTitle()) and not v.widget().windowIcon().isNull():
                        tabGroup.setTabIcon(i, v.widget().windowIcon()) 

#############  END OF DOCKWIDGETS FUNCTIONS ###############

    def applyModule(self, modname, modtype, selected):
        appMod = ApplyModule(self)
        appMod.openApplyModule(modname, modtype, selected)

    def initCallback(self):
        self.sched.set_callback("add_qwidget", self.qwidgetResult)
        self.connect(self, SIGNAL("qwidgetResultView"), self.qwidgetResultView)
        self.connect(self, SIGNAL("strResultView"), self.strResultView)

    def qwidgetResult(self, qwidget):
        self.emit(SIGNAL("qwidgetResultView"), qwidget)
 
    def strResult(self, proc):
        self.emit(SIGNAL("strResultView"), proc)

    def qwidgetResultView(self, proc):
	try :
           proc.inst.g_display()
           self.addDockWidgets(proc.inst, proc.name)
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
           self.addDockWidgets(widget, proc.name)

    def addToolBars(self, action):
        """ Init Toolbar"""
        if not action:
            #Add separator
            self.toolBar.addSeparator()
        else:
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
        for action in self.toolbarList:
	   self.addToolBars(action)

    def createRootNodes(self):
        root = self.vfs.getnode('/')
        self.devicenode = deviceNode(root, str('Local devices'))
        self.logicalenode = logicalNode(root, str('Logical files'))
        self.searchednode = searchNode(root, str('Searched items'))
        self.booknode = bookNode(root, str('Bookmarks'))

    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
            self.translation()
        else:
            QMainWindow.changeEvent(self, event)

    def translation(self):
        self.errorLoadingHelp = self.tr('Error while loading help')
        self.onlineHelp = self.tr('<br>You can check on-line help at <a href=\"http://wiki.digital-forensic.org/\">http://wiki.digital-forensic.org</a>.')
        self.notAnHelpFile = self.tr('Not an help file.') + self.onlineHelp
        self.noSuchHelpFile = self.tr('Documentation path not found.') + self.onlineHelp


class deviceNode(Node):
    def __init__(self, parent, name):
        Node.__init__(self, name, 0, parent, None)
        self.__disown__()
        self.setDir()

    def icon(self):
        return (":dev_hd.png")

class logicalNode(Node):
    def __init__(self, parent, name):
        Node.__init__(self, name, 0, parent, None)
        self.__disown__()
        self.setDir()

    def icon(self):
        return (":folder_documents_128.png")
    
class bookNode(Node):
    def __init__(self, parent, name):
        Node.__init__(self, name, 0, parent, None)
        self.__disown__()
        self.setDir()

    def icon(self):
        return (":bookmark.png")

class searchNode(Node):
    def __init__(self, parent, name):
        Node.__init__(self, name, 0, parent, None)
        self.__disown__()
        self.setDir()

    def icon(self):
        return (":hex_search.png")

