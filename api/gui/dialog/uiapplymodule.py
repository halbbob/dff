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

from PyQt4 import QtCore, QtGui

class UiApplyModule(object):
    def setupUi(self, applyModule):
        applyModule.setObjectName("applyModule")
        applyModule.setWindowModality(QtCore.Qt.ApplicationModal)
#        applyModule.resize(QtCore.QSize(QtCore.QRect(0,0,421,440).size()).expandedTo(applyModule.minimumSizeHint()))
        applyModule.setMinimumWidth(640)

#        self.label = QtGui.QLabel(applyModule)
#        self.label.setGeometry(QtCore.QRect(9,9,403,20))

#        font = QtGui.QFont()
#        font.setPointSize(10)
#        font.setWeight(75)
#        font.setBold(True)
#        self.label.setFont(font)
#        self.label.setObjectName("label")

        self.buttonBox = QtGui.QDialogButtonBox(applyModule)
#        self.buttonBox.setGeometry(QtCore.QRect(9,403,403,28))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.NoButton|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")

        self.retranslateUi(applyModule)
        QtCore.QObject.connect(self.buttonBox,QtCore.SIGNAL("rejected()"),applyModule.reject)
        QtCore.QMetaObject.connectSlotsByName(applyModule)

    def retranslateUi(self, applyModule):
        applyModule.setWindowTitle(self.tr("applyModule", "Apply Module"))
#        self.label.setText(self.tr("applyModule", " Scripts and Drivers:"))

