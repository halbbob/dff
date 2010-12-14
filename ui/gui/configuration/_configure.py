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

from PyQt4 import QtCore, QtGui

class UiConfigure(object):
    def setupUi(self, Configure):
        Configure.setObjectName("Configure")
        Configure.setWindowModality(QtCore.Qt.ApplicationModal)
        Configure.resize(QtCore.QSize(QtCore.QRect(0,0,508,132).size()).expandedTo(Configure.minimumSizeHint()))

        self.layoutWidget = QtGui.QWidget(Configure)
        self.layoutWidget.setGeometry(QtCore.QRect(10,10,491,111))
        self.layoutWidget.setObjectName("layoutWidget")

        self.vboxlayout = QtGui.QVBoxLayout(self.layoutWidget)
        self.vboxlayout.setObjectName("vboxlayout")

        self.hboxlayout = QtGui.QHBoxLayout()
        self.hboxlayout.setObjectName("hboxlayout")

        self.label = QtGui.QLabel(self.layoutWidget)
        self.label.setMinimumSize(QtCore.QSize(120,28))
        self.label.setMaximumSize(QtCore.QSize(120,28))

        font = QtGui.QFont()
        font.setPointSize(10)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.hboxlayout.addWidget(self.label)

        self.LanguageBox = QtGui.QComboBox(self.layoutWidget)
        self.LanguageBox.setObjectName("LanguageBox")
        self.hboxlayout.addWidget(self.LanguageBox)
        self.vboxlayout.addLayout(self.hboxlayout)

        self.hboxlayout1 = QtGui.QHBoxLayout()
        self.hboxlayout1.setObjectName("hboxlayout1")

        self.labelWorkspace = QtGui.QLabel(self.layoutWidget)
        self.labelWorkspace.setMinimumSize(QtCore.QSize(120,28))
        self.labelWorkspace.setMaximumSize(QtCore.QSize(120,28))

        font = QtGui.QFont()
        font.setPointSize(10)
        self.labelWorkspace.setFont(font)
        self.labelWorkspace.setObjectName("labelWorkspace")
        self.hboxlayout1.addWidget(self.labelWorkspace)

        self.valueWorkspace = QtGui.QLineEdit(self.layoutWidget)
        self.valueWorkspace.setObjectName("valueWorkspace")
        self.hboxlayout1.addWidget(self.valueWorkspace)

        self.buttonSelectWorkspace = QtGui.QPushButton(self.layoutWidget)
        self.buttonSelectWorkspace.setMinimumSize(QtCore.QSize(75,28))
        self.buttonSelectWorkspace.setMaximumSize(QtCore.QSize(75,28))
        self.buttonSelectWorkspace.setObjectName("buttonSelectWorkspace")
        self.hboxlayout1.addWidget(self.buttonSelectWorkspace)
        self.vboxlayout.addLayout(self.hboxlayout1)

        self.buttonBox = QtGui.QDialogButtonBox(self.layoutWidget)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.NoButton|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.vboxlayout.addWidget(self.buttonBox)

        self.retranslateUi(Configure)
        QtCore.QObject.connect(self.buttonBox,QtCore.SIGNAL("accepted()"),Configure.accept)
        QtCore.QObject.connect(self.buttonBox,QtCore.SIGNAL("rejected()"),Configure.reject)
        QtCore.QMetaObject.connectSlotsByName(Configure)

    def retranslateUi(self, Configure):
        Configure.setWindowTitle(self.tr("Configure", "Configure"))
        self.label.setText(self.tr("Configure", "Language:"))
        self.labelWorkspace.setText(self.tr("Configure", "Extract Folder:"))
        self.buttonSelectWorkspace.setText(self.tr("Configure", "Browser"))
