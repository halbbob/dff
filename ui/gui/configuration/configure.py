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
#  Francois Percot <percot@gmail.com>
# 

# Form Custom implementation of CONFIGUREDFF
from PyQt4.QtCore import SIGNAL
from PyQt4.QtGui import QApplication, QDialog, QFileDialog

# Import the template generate by QtDesigner
from _configure import UiConfigure

# Import Singleton for CONF
from conf import Conf

# QDialog for Fill the information about the newCase
class ConfigureDialog(QDialog,  UiConfigure):
    def __init__(self,  parent):
        QDialog.__init__(self,  parent)
        UiConfigure.__init__(self)
        self.setupUi(self)
        self.Conf = Conf()
        self.initLanguage()
        self.connect(self.buttonSelectWorkspace,  SIGNAL("clicked()"), self.selectWorkspace)
    
    def initLanguage(self):
        pass
    
    # Get the information about the config
    def getAllInfo(self):
        lParam = []
        lParam.append(self.LanguageBox.currentIndex())
        lParam.append(self.valueWorkspace.text())
        return lParam
        
    def selectWorkspace(self):
        sDirPath = QFileDialog.getExistingDirectory(self, self.tr("Configure", "Choose Your Directory For Extraction"),  "/home")
        if (sDirPath) :
            self.valueWorkspace.setText(sDirPath)
