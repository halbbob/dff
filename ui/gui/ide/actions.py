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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 

from PyQt4.QtCore import *
from PyQt4.QtGui import *

from dockide import DockIde

class IdeActions(QObject):
    def __init__(self, mainwindow, ide = None):
        QObject.__init__(self)
        self.mainwindow = mainwindow
        self.ide = ide

        self.init()
        self.initMainActions()
        self.initIdeActions()

        self.initMainToolbar()
        self.initIdeToolbar()

        self.setMenu()

        self.initMainCallBacks()

        self.disableActions()
        self.mainwindow.menubar.addAction(self.menu.menuAction())
        self.mainwindow.addToolBar(Qt.TopToolBarArea, self.maintoolbar)

    def init(self):
        self.mainActs = []
        self.ideActs = []

    def initMainCallBacks(self):
        self.newact.connect(self.newact,  SIGNAL("triggered()"), self.newScript)
        self.openact.connect(self.openact,  SIGNAL("triggered()"), self.openScript)

    def initMainActions(self):
        self.maintoolbar = QToolBar()
        self.maintoolbar.setObjectName('ide action toolbar')

        self.newact = QAction(QIcon(":script-new.png"),  self.tr("New script"),  self.maintoolbar)
        self.mainActs.append(self.newact)

        self.openact = QAction(QIcon(":script-open.png"),  self.tr("Open script"),  self.maintoolbar)
        self.mainActs.append(self.openact)

    def initMainToolbar(self):
        self.maintoolbar.addAction(self.newact)
        self.maintoolbar.addAction(self.openact)
 
    def initIdeActions(self):
        self.idetoolbar = QToolBar()

        self.saveact = QAction(QIcon(":script-save.png"),  self.tr("Save script"),  self.idetoolbar)
        self.ideActs.append(self.saveact)
    
        self.saveasact = QAction(QIcon(":script-save-as.png"),  self.tr("Save script as"),  self.idetoolbar)
        self.ideActs.append(self.saveasact)
        
        self.runact = QAction(QIcon(":script-run.png"),  self.tr("Load script"),  self.idetoolbar)
        self.ideActs.append(self.runact)
        
        self.undoact = QAction(QIcon(":undo.png"),  self.tr("Undo"),  self.idetoolbar)
        self.ideActs.append(self.undoact)
        
        self.redoact = QAction(QIcon(":redo.png"),  self.tr("Redo"),  self.idetoolbar)
        self.ideActs.append(self.redoact)
   
    def initIdeToolbar(self):
        self.idetoolbar.addAction(self.saveact)
        self.idetoolbar.addAction(self.saveasact)
        self.idetoolbar.addAction(self.runact)
        self.idetoolbar.addAction(self.undoact)
        self.idetoolbar.addAction(self.redoact)


    def enableActions(self):
        self.newact.setEnabled(True)
        self.openact.setEnabled(True)

        self.saveact.setEnabled(True)
        self.saveasact.setEnabled(True)
        self.runact.setEnabled(True)
        self.undoact.setEnabled(True)
        self.redoact.setEnabled(True)

    def disableActions(self):
        self.newact.setEnabled(True)
        self.openact.setEnabled(True)

        self.saveact.setEnabled(False)
        self.saveasact.setEnabled(False)
        self.runact.setEnabled(False)
        self.undoact.setEnabled(False)
        self.redoact.setEnabled(False)

    # CALLBACKS
    def newScript(self):
        if not self.ide:
            self.dockide = DockIde(self.mainwindow, self)
            self.mainwindow.dockWidget["IDE"] = self.dockide
            self.mainwindow.addNewDockWidgetTab(self.mainwindow.mainArea, self.dockide)
        self.dockide.ide.newactBack()
        
    def openScript(self):
#          if not self.dockide:
        try:
	  self.dockide
          pass
        except AttributeError:
            self.dockide = DockIde(self.mainwindow, self)
            self.mainwindow.dockWidget["IDE"] = self.dockide
            self.mainwindow.addNewDockWidgetTab(self.mainwindow.mainArea, self.dockide)

        self.dockide.ide.openactBack()


    def setMenu(self):
        self.menu = QMenu(self.mainwindow.menubar)
        self.menu.setObjectName("menuIde")
        self.menu.setTitle(self.tr("IDE"))

        self.menu.addAction(self.newact)
        self.menu.addAction(self.openact)
        
        self.menu.addSeparator()

        self.menu.addAction(self.saveact)
        self.menu.addAction(self.saveasact)
        self.menu.addAction(self.runact)

        self.menu.addSeparator()

        self.menu.addAction(self.undoact)
        self.menu.addAction(self.redoact)

        

