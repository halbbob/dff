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

import sys

from PyQt4.QtGui import QApplication, QSplashScreen, QPixmap
from PyQt4.QtCore import Qt

from mainwindow import MainWindow
from translator import Translator
from api.loader.loader import loader

from ui.gui.resources import gui_rc

class SplashScreen(QSplashScreen):
  def __init__(self, pixmap, windowFlag, versionNumber):
     QSplashScreen.__init__(self, pixmap, windowFlag)
     self.versionNumber = versionNumber

  def drawContents(self, painter):
     QSplashScreen.drawContents(self, painter) 
     painter.drawText(10, 178, "Version " + str(self.versionNumber))	

class gui():
    def __init__(self, debug = False):
        """Launch GUI"""
        self.debug = debug
        self.app = QApplication(sys.argv)

        self.translator = Translator()
        
        self.app.installTranslator(self.translator.getGeneric())
        self.app.installTranslator(self.translator.getDFF())
        self.app.setApplicationName("Digital Forensics Framework")
	self.app.setApplicationVersion("1.2.0")
        pixmap = QPixmap(":splash.png")
        self.splash = SplashScreen(pixmap, Qt.WindowStaysOnTopHint, self.app.applicationVersion())
        self.splash.setMask(pixmap.mask()) 

    def launch(self, modPath = None):
        self.splash.show()
        if modPath:
          self.loader = loader()
          self.loader.do_load(modPath, self.splash.showMessage)
        mainWindow = MainWindow(self.app, self.debug)
        mainWindow.show()

        self.splash.finish(mainWindow)
        sys.exit(self.app.exec_())

