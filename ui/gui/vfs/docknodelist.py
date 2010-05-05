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

from PyQt4.QtCore import QSize, SIGNAL, pyqtSignature
from PyQt4.QtGui import QDockWidget, QWidget, QVBoxLayout, QHBoxLayout, QIcon, QComboBox, QPushButton, QSortFilterProxyModel
from PyQt4.Qt import *

from api.gui.itemview.listview import ListView
from api.gui.itemview.listmodel import ListModel
from api.gui.widget.nodelist import NodeList

from ui.gui.utils.menu import MenuTags, MenuModules


import os

#Need some APIs functionnalities
from api.magic.filetype import *
from api.loader import *
from api.taskmanager.taskmanager import *
from api.env import *
 
class DockNodeList(QDockWidget):
    def __init__(self, mainWindow, dockBrowser, nbr):
        QDockWidget.__init__(self, mainWindow)
        self.configure()
        self.addAction(mainWindow,  nbr)
        self.g_display(mainWindow, dockBrowser)
        self.initCallback()
        self.setObjectName("NodeBrowserDock " + str(nbr))

    def configure(self):
        self.setAllowedAreas(Qt.AllDockWidgetAreas)
        self.setWindowTitle(QApplication.translate("NodeBrowserDock", "NodeBrowserDock", None, QApplication.UnicodeUTF8))
    
    def addAction(self, mainWindow, nbr):
        self.action = QAction(self)
        self.action.setCheckable(True)
        self.action.setChecked(True)
        self.action.setObjectName("actionCoreInformations")
        self.action.setText(QApplication.translate("MainWindow", "List Files", None, QApplication.UnicodeUTF8) + str(nbr))
        self.connect(self.action,  SIGNAL("triggered()"),  self.changeVisibleInformations)
    
    def changeVisibleInformations(self):
        if not self.isVisible() :
            self.setVisible(True)
            self.action.setChecked(True)
        else :
            self.setVisible(False)
            self.action.setChecked(False)
            
    def g_display(self, mainWindow, dockBrowser):
        self.listwidget = NodeList(self, mainWindow, dockBrowser)
        self.setWidget(self.listwidget)
    
    def initCallback(self):
        self.connect(self, SIGNAL("visibilityChanged(bool)"), self.changedVisibility)
    
    def initContents(self, node, index):
        self.listwidget.showFolder(node, index, 2)
    
    def changedVisibility(self, bool):
        if not self.isVisible() and not bool :
	     pass
        if bool :
            self.listwidget.setChildSelected()
        


