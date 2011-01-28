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

from ui.gui.ide.idewizard import IdeWizard

from ui.gui.ide.generatecode import GenerateCode
from ui.gui.ide.messagebox import MessageBoxWarningSave,  MessageBoxErrorSave
from ui.gui.ide.editor import codeEditor
from ui.gui.ide.explorer import Explorer


from api.loader import *

class Ide(QWidget):
    def __init__(self, parent):
        super(Ide,  self).__init__(parent)
        self.loader = loader.loader()
#        self.actions = parent.actions
        self.name = "IDE"
        self.pages = []
        self.mainWindow = parent
        self.toolbar = QToolBar()
        self.toolbar.setObjectName('IDE_toolbar')

#        self.mainwindow.toolBar.addAction(self.newact)
        self.initActions()
        self.initCallBacks()
        self.setupToolbar()
        self.g_display()
        
    def initActions(self):
        self.newemptyact = QAction(QIcon(":empty.png"),  self.tr("New empty file"),  self.toolbar)
        self.newact = QAction(QIcon(":script-new.png"),  self.tr("Generate script"),  self.toolbar)
        self.openact = QAction(QIcon(":script-open.png"),  self.tr("Open script"),  self.toolbar)
        self.saveact = QAction(QIcon(":script-save.png"),  self.tr("Save script"),  self.toolbar)
        self.saveasact = QAction(QIcon(":script-save-as.png"),  self.tr("Save script as"),  self.toolbar)
        self.runact = QAction(QIcon(":script-run.png"),  self.tr("Load script"),  self.toolbar)
        self.undoact = QAction(QIcon(":undo.png"),  self.tr("Undo"),  self.toolbar)
        self.redoact = QAction(QIcon(":redo.png"),  self.tr("Redo"),  self.toolbar)
        self.commentact = QAction(QIcon(":comment.png"),  self.tr("Comment"),  self.toolbar)
        self.uncommentact = QAction(QIcon(":uncomment.png"),  self.tr("Uncomment"),  self.toolbar)
#        self.redoact = QAction(QIcon(":search.png"),  self.tr("Find"),  self.toolbar)

    def initCallBacks(self):
        self.newemptyact.connect(self.newemptyact,  SIGNAL("triggered()"), self.newempty)
        self.newact.connect(self.newact,  SIGNAL("triggered()"), self.new)
        self.openact.connect(self.openact,  SIGNAL("triggered()"), self.open)
        self.saveact.connect(self.saveact,  SIGNAL("triggered()"), self.save)
        self.saveasact.connect(self.saveasact,  SIGNAL("triggered()"), self.saveAs)
        self.runact.connect(self.runact,  SIGNAL("triggered()"), self.run)
        self.undoact.connect(self.undoact,  SIGNAL("triggered()"), self.undo)
        self.redoact.connect(self.redoact,  SIGNAL("triggered()"), self.redo)
        self.commentact.connect(self.commentact,  SIGNAL("triggered()"), self.comment)
        self.uncommentact.connect(self.uncommentact,  SIGNAL("triggered()"), self.uncomment)

    def setupToolbar(self):
        self.toolbar.addAction(self.newemptyact)
        self.toolbar.addAction(self.newact)
        self.toolbar.addAction(self.openact)
        self.toolbar.addAction(self.saveact)
        self.toolbar.addAction(self.saveasact)
        self.toolbar.addAction(self.runact)
        self.toolbar.addAction(self.undoact)
        self.toolbar.addAction(self.redoact)
        self.toolbar.addAction(self.commentact)
        self.toolbar.addAction(self.uncommentact)

    def g_display(self):
        self.vbox = QVBoxLayout()
        self.vbox.setSpacing(0)
        self.vbox.setMargin(0)
        self.vbox.addWidget(self.toolbar)

        self.splitter = QSplitter()
        self.createExplorer()
        self.createTabWidget()
        self.splitter.setSizes([1, 4])
        self.vbox.addWidget(self.splitter)
        self.refreshToolbar()
        self.setLayout(self.vbox)

    def createExplorer(self):
        self.explorer = Explorer(parent=self)
        self.splitter.addWidget(self.explorer)

    def createTabWidget(self):
        self.scripTab = QTabWidget()
        self.buttonCloseTab = QPushButton("")
        self.buttonCloseTab.setFixedSize(QSize(23,  23))
        self.buttonCloseTab.setIcon(QIcon(":cancel.png"))
        self.buttonCloseTab.setEnabled(False)
        self.scripTab.setCornerWidget(self.buttonCloseTab,  Qt.TopRightCorner)
        self.scripTab.connect(self.buttonCloseTab, SIGNAL("clicked()"), self.closeTabWidget)
        self.splitter.addWidget(self.scripTab)

    def createPage(self,  buffer):
        page = codeEditor()
        page.setPlainText(QString(buffer))
        self.pages.append(page)
        return page

    def new(self):
        self.ideWiz = IdeWizard(self, self.tr("New script"))
        ret = self.ideWiz.exec_()
        if ret > 0:
            scriptname = self.ideWiz.field("name").toString()
            path = self.ideWiz.field("path").toString()
            stype = self.ideWiz.field("typeS").toBool()
            gtype = self.ideWiz.field("typeG").toBool()
            dtype = self.ideWiz.field("typeD").toBool()
            tag = self.ideWiz.field("category").toString()
            category = self.ideWiz.PIntro.category.currentText()
            description = self.ideWiz.field("description").toString()
            authfname = self.ideWiz.field("authFName").toString()
            authlname = self.ideWiz.field("authLName").toString()
            authmail = self.ideWiz.field("authMail").toString()

            generate = GenerateCode()
            generate.set_header(authfname, authlname, authmail)
            generate.setTag(category)
            generate.setDescription(description)
            if stype == True:
                buffer = generate.generate_script(str(scriptname))
                scin = self.createPage(buffer)
            if dtype == True:
                buffer = generate.generate_drivers(str(scriptname))
                scin = self.createPage(buffer)
            if gtype == True:
                buffer = generate.generate_script_gui(str(scriptname))
                scin = self.createPage(buffer)
            
            filename = scriptname + ".py"                
            scin.setName(filename)

            if path[-1] != "/":
                path += "/"
            lpath = path + filename
            scin.setScriptPath(lpath)
            self.scripTab.addTab(scin,  filename)
            self.buttonCloseTab.setEnabled(True)
            self.refreshToolbar()

    def newempty(self):
        page = self.createPage("")
        name = "Default_" + self.checkTabNames("Default")
        page.setName(name)
        self.scripTab.addTab(page,  name)
        self.buttonCloseTab.setEnabled(True)
        self.refreshToolbar()

    def checkTabNames(self, name):
        tab = self.scripTab.tabBar()
        cp = 0
        for i in xrange(tab.count()):
            if tab.tabText(i).startsWith(name):
                cp += 1
        return str(cp)
    
    def open(self, path=None):
        if path == None:
            sFileName = QFileDialog.getOpenFileName(self.parent, self.tr("MainWindow", "open"),"/home")
        else:
            sFileName = path
        if sFileName:
            file = open(sFileName,  "r")
            page = self.createPage("")
            buffer = QString()
            buffer = file.read()
            page.setPlainText(buffer)
            script = sFileName.split("/")
            
            scriptname = script[len(script) - 1]
            page.setName(scriptname)
            
            page.setScriptPath(sFileName)
            self.scripTab.addTab(page,  scriptname)
            self.buttonCloseTab.setEnabled(True)
            file.close
    
    def save(self):
        index = self.scripTab.currentIndex()
        page = self.pages[index]
        path = page.getScriptPath()
        if not path.isEmpty():
            file = open(path,  "w")
            file.write(page.toPlainText())
            file.close()
        else:
            self.saveasactBack()
            
    def saveAs(self):
        index = self.scripTab.currentIndex()
        title = self.scripTab.tabText(index)
        if title:
            sFileName = QFileDialog.getSaveFileName(self, self.tr("MainWindow", "Save as"),title)
            page = self.pages[index]
            file = open(str(sFileName),"w")
            file.write(page.toPlainText())
            file.close()
        
    def run(self):
        if self.scripTab.count() > 0:
            index = self.scripTab.currentIndex()
            page = self.pages[index]
            self.saveactBack()

            path = page.getScriptPath()
            self.loader.do_load(str(path))
        else:
            print "No script found"
        
    def undo(self):
        if self.scripTab.count() > 0:
            index = self.scripTab.currentIndex()
            page = self.pages[index]
            page.undo()

    def redo(self):
        if self.scripTab.count() > 0:
            index = self.scripTab.currentIndex()
            page = self.pages[index]
            page.redo()

    def comment(self):
        if self.scripTab.count() > 0:
            index = self.scripTab.currentIndex()
            page = self.pages[index]
            page.comment()

    def uncomment(self):
        if self.scripTab.count() > 0:
            index = self.scripTab.currentIndex()
            page = self.pages[index]
            page.uncomment()


    def refreshToolbar(self):
        if self.scripTab.count() == 0:
            self.saveact.setEnabled(False)
            self.saveasact.setEnabled(False)
            self.runact.setEnabled(False)
            self.undoact.setEnabled(False)
            self.redoact.setEnabled(False)
        else:
            self.saveact.setEnabled(True)
            self.saveasact.setEnabled(True)
            self.runact.setEnabled(True)
            self.undoact.setEnabled(True)
            self.redoact.setEnabled(True)

    def closeTabWidget(self):
        if self.scripTab.count() > 0:
            index = self.scripTab.currentIndex()
            currentPage = self.scripTab.currentWidget()
            warning = MessageBoxWarningSave(self,  "Save document?")
            warning.exec_()

            self.scripTab.removeTab(index)
            page = self.pages[index]
            self.pages.remove(page)
            currentPage.destroy(True, True)
            if self.scripTab.count() == 0:
                self.buttonCloseTab.setEnabled(False)
                self.refreshToolbar()

#                self.mainWindow.Ide_toolBar.disableToolbar()

   
