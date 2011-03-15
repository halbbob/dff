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

from PyQt4.QtGui import QCheckBox
from PyQt4.QtCore import QObject, QSize, Qt, SIGNAL

class checkBoxWidget(QCheckBox):
    def __init__(self, parent, info, widget, label):
        QCheckBox.__init__(self)
        self.__info = info
        self.__widget = widget
        self.setText(label)
        self.stateChangedWidget(Qt.Unchecked)
        self.initCallback()
    
    def initCallback(self):
        self.connect(self, SIGNAL("stateChanged(int )"), self.stateChangedWidget)
    
    def stateChangedWidget(self,  state):
        if state == Qt.Checked :
            if self.__widget:
                self.__widget.setEnabled(1)
            self.__info.setEnabled(1)
        else :
            if self.__widget:
                self.__widget.setEnabled(0)
            self.__info.setEnabled(0)
        
