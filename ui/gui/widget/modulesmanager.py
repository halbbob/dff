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
#  Solal Jacob <sja@digital-forensic.org>
#  Jeremy MOUNIER <jmo@digital-forensic.org>
#

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from api.loader import *
from api.taskmanager.taskmanager import *

from ui.gui.utils.utils import Utils

from api.gui.widget.generateModuleShape import *

from ui.gui.resources.ui_modulebrowserdialog import Ui_moduleBrowser

#class moduleBrowser(QDialog):

class browserDialog(QDialog, Ui_moduleBrowser):
    def __init__(self, main):
        QDialog.__init__(self)
        Ui_moduleGeneratorWidget.__init__(self)
    
        self.setupUi(self)

        self.main = main

        self.browser = modulesManager(self)

        self.lcontainer.addWidget(self.browser)


class modulesManager(QWidget):
    def __init__(self, parent):
        QWidget.__init__(self, parent)
        self.name = "moduleManager"
        self.initShape()

    def initShape(self):
        self.mainvbox = QVBoxLayout()
        self.splitter = QSplitter()
        self.splitter.setOrientation(Qt.Vertical)

        self.stacked = stackedWidget(self)
        self.toolbox = tabBox(self)

        self.splitter.addWidget(self.toolbox)
        self.splitter.addWidget(self.stacked)

        self.mainvbox.addWidget(self.splitter)
        self.setLayout(self.mainvbox)

        cw = self.toolbox.currentWidget()
#        print cw
#        print cw.item(0).text()
        cw.setCurrentItem(cw.item(0))
        cw.emit(SIGNAL("itemPressed(QListWidgetItem *)"), cw.item(0))


    def execute(self):
        self.stacked.currentWidget().validateModule()

class stackedWidget(QStackedWidget):
    def __init__(self, parent):
        QStackedWidget.__init__(self)
        self.previousw = None


class tabBox(QTabWidget):
    def __init__(self, parent):
        QTabWidget.__init__(self)
        self.stacked = parent.stacked
        self.browser = parent
        self.tags = Utils.getSetTags()
        self.itemWidgets = []
        self.fillToolBox()

    def fillToolBox(self):
        for tag in self.tags:
            if tag != "builtins":
                itemw = itemWidget(tag, self)
                self.addTab(itemw.getList(), tag)

#class toolBox(QToolBox):
#    def __init__(self, parent):
#        QToolBox.__init__(self, parent)
#        self.tags = Utils.getSetTags()
#        self.browser = parent
#        self.stacked = parent.stacked
#        self.itemWidgets = []
#        self.fillToolBox()

#    def fillToolBox(self):
#        for tag in self.tags:
#            print tag
#            if tag != "builtins":
#                itemw = itemWidget(tag, self)
#                self.addItem(itemw.getList(), tag)

class listWidget(QListWidget):
    def __init__(self, stacked):
        QListWidget.__init__(self)
        self.stacked = stacked
        self.loader = loader.loader()

        self.setResizeMode(QListView.Adjust)
        self.setMovement(QListView.Static)
        self.setViewMode(QListView.IconMode)

        self.connect(self, SIGNAL("itemPressed(QListWidgetItem *)"), self.GMShape)

    def GMShape(self, item):
        module = self.loader.modules[str(item.text())]

        if self.stacked.previousw:
           self.stacked.removeWidget(self.stacked.previousw)
           self.stacked.previousw.close()
           del self.stacked.previousw

        msgen = moduleShapeGenerator(module.name, module.tags)

        self.stacked.previousw = msgen
        self.stacked.addWidget(self.stacked.previousw)


class itemWidget():
    def __init__(self, tag, box):
        self.tag = tag
        self.box = box
        self.browser = box.browser
        self.stacked = box.stacked
        self.loader = loader.loader()
        self.itemodules = []

        self.getModules()
        self.listw = None

    def getModules(self):
        self.modules = self.loader.modules
        for mod in self.modules :
            m = self.modules[mod]
            try :
                if m.tags == self.tag:
 #                   if not self.browser.firstModule:
#                        self.browser.firstModule = m
                    self.itemodules.append(m)
            except AttributeError, e:
		pass

    def getList(self):
        if not self.listw:
            self.listw = listWidget(self.stacked)
            # self.listw.setViewMode(QListView.IconMode)
            for mod in self.itemodules:
                if mod.icon:
                    icon = QIcon(QPixmap(mod.icon))
                else:
                    icon = QIcon(QPixmap(":module2.png"))
                item = QListWidgetItem(icon, mod.name, self.listw)
                self.listw.addItem(item)
            return self.listw
        else:
            return self.listw

