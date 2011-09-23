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
#

from PyQt4.QtGui import QStackedWidget, QIcon, QPixmap, QApplication, QWidget
from PyQt4.QtCore import QRect, QSize, Qt, SIGNAL, QEvent

from api.loader.loader import loader


class Preview(QStackedWidget):
    def __init__(self, parent):
        super(QStackedWidget, self).__init__()
        self.__mainWindow = parent        
        self.name = self.tr("Preview")
        self.loader = loader()
	self.lmodules = self.loader.modules
	void = QWidget()
	self.previousWidget = void 
	self.addWidget(void)
        self.setWindowIcon(QIcon(QPixmap(":viewer.png")))
        self.retranslateUi(self) 
        self.previousNode = None       
	self.mustUpdate = True

    def setUpdate(self, state):
       self.mustUpdate = state 

    def update(self, node):
       if self.isVisible() and self.mustUpdate and node.size():
         if self.previousNode == node.this:
	   return
         else:
	   self.previousNode = node.this 	
         previewModule = None
         compat = node.compatibleModules()
         if len(compat):
   	   for module in compat:
	     if "Viewers" in self.lmodules[module].tags:
	      previewModule = module
	      break
         if not previewModule:
	   previewModule = "hexadecimal"  
	 if self.previousWidget:
  	   self.removeWidget(self.previousWidget)
	   self.previousWidget.close()
	   del self.previousWidget
	 args = {}
	 args["file"]  = node
 	 args["preview"] = True
	 conf = self.loader.get_conf(str(previewModule))
  	 genargs = conf.generate(args)
	 self.previousWidget = self.lmodules[previewModule].create()
	 self.previousWidget.start(genargs)
	 self.previousWidget.g_display()
         if str(self.previousWidget).find("player.PLAYER") == -1:
             self.previousWidget.setAttribute(Qt.WA_DeleteOnClose)
	 self.addWidget(self.previousWidget)

    def retranslateUi(self, widget):
       widget.setWindowTitle(QApplication.translate("Preview", "Preview", None, QApplication.UnicodeUTF8))
