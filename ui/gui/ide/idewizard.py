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

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from idewizardpages import *

class IdeWizard(QWizard):
    def __init__(self, mainWindow, title):
        super(IdeWizard,  self).__init__(mainWindow)
        self.main = mainWindow
        self.setWindowTitle(self.tr("Integrated Development Environment Wizard"))

        self.setOrder()
        self.setPages()

    def setOrder(self):
        self.porder = {}
        self.porder['INTRO'] = 0
        self.porder['DESCRIPTION'] = 1
        self.porder['AUTH'] = 2

    def setPages(self):
        self.PIntro = WIntroPage(self)
        self.PAuth = WAuthorPage(self)
        self.PDescription = WDescriptionPage(self)

        self.setPage(self.porder['INTRO'], self.PIntro)
        self.setPage(self.porder['DESCRIPTION'], self.PDescription)
        self.setPage(self.porder['AUTH'], self.PAuth)
        
        
    def nextId(self):
        current = self.currentId()
        if current == self.porder['INTRO']:
            return self.porder['DESCRIPTION']
        elif current == self.porder['DESCRIPTION']:
            return self.porder['AUTH']
        else:
            return -1
