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
#  Solal Jacob <sja@digital-forensic.org>
# 

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *

class NodeFilterBox(QGroupBox):
  def __init__(self, parent):
    QGroupBox.__init__(self, "Find file")
    self.parent = parent

    self.sortCaseSensitivityCheckBox = QCheckBox("Case sensitive sorting")
    self.filterCaseSensitivityCheckBox = QCheckBox("Case sensitive filter")

    self.filterPatternLineEdit = QLineEdit()
    self.filterPatternLabel = QLabel("Pattern:")
    self.filterPatternLabel.setBuddy(self.filterPatternLineEdit)
    self.filterPatternLineEdit.setText("")

    self.filterSyntaxComboBox = QComboBox()
    self.filterSyntaxComboBox.addItem("Regular expression",
                QVariant(QtCore.QRegExp.RegExp))
    self.filterSyntaxComboBox.addItem("Wildcard",
                QVariant(QtCore.QRegExp.Wildcard))
    self.filterSyntaxComboBox.addItem("Fixed string",
                QVariant(QtCore.QRegExp.FixedString))
    self.filterSyntaxLabel = QLabel("Syntax:")
    self.filterSyntaxLabel.setBuddy(self.filterSyntaxComboBox)

    self.filterColumnComboBox = QComboBox()
    self.filterColumnComboBox.addItem(self.tr("Name"))
    self.filterColumnComboBox.addItem(self.tr("Size"))
    self.filterColumnComboBox.addItem(self.tr("Date"))
    self.filterColumnComboBox.setCurrentIndex(0)
    self.filterColumnLabel = QLabel(self.tr("Attribute:"))
    self.filterColumnLabel.setBuddy(self.filterColumnComboBox)

    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.filterPatternLineEdit.textChanged.connect(self.filterRegExpChanged)
      self.filterSyntaxComboBox.currentIndexChanged.connect(self.filterRegExpChanged)
      self.filterColumnComboBox.currentIndexChanged.connect(self.filterColumnChanged)
      self.filterCaseSensitivityCheckBox.toggled.connect(self.filterRegExpChanged)
      self.sortCaseSensitivityCheckBox.toggled.connect(self.sortChanged)
    else:
      QtCore.QObject.connect(self.filterPatternLineEdit, SIGNAL("textChanged(QString)"), self.filterRegExpChanged)
      QtCore.QObject.connect(self.filterSyntaxComboBox, SIGNAL("currentIndexChanged(int)"), self.filterRegExpChanged)
      QtCore.QObject.connect(self.filterColumnComboBox, SIGNAL("currentIndexChanged(int)"), self.filterColumnChanged)
      QtCore.QObject.connect(self.filterCaseSensitivityCheckBox, SIGNAL("toggled(bool)"), self.filterRegExpChanged)
      QtCore.QObject.connect(self.sortCaseSensitivityCheckBox, SIGNAL("toggled(bool)"), self.sortChanged)
    self.filterCaseSensitivityCheckBox.setChecked(True)
    self.sortCaseSensitivityCheckBox.setChecked(True)

    proxyLayout = QGridLayout()
    proxyLayout.addWidget(self.filterPatternLabel, 0, 0)
    proxyLayout.addWidget(self.filterPatternLineEdit, 0, 1, 1, 2)
    proxyLayout.addWidget(self.filterSyntaxLabel, 1, 0)
    proxyLayout.addWidget(self.filterSyntaxComboBox, 1, 1, 1, 2)
    proxyLayout.addWidget(self.filterColumnLabel, 2, 0)
    proxyLayout.addWidget(self.filterColumnComboBox, 2, 1, 1, 2)
    proxyLayout.addWidget(self.filterCaseSensitivityCheckBox, 3, 0, 1, 2)
    proxyLayout.addWidget(self.sortCaseSensitivityCheckBox, 3, 2)
    self.setLayout(proxyLayout)
    self.setVisible(False)

  def filterRegExpChanged(self):
        if self.filterCaseSensitivityCheckBox.isChecked():
            caseSensitivity = Qt.CaseSensitive
        else:
            caseSensitivity = Qt.CaseInsensitive
        regExp = QRegExp(self.filterPatternLineEdit.text(), caseSensitivity)
        regExp.setPatternSyntax(self.filterSyntaxComboBox.currentIndex())
        if self.parent.currentProxyModel():
          self.parent.currentProxyModel().setFilterRegExp(regExp)

  def filterColumnChanged(self):
        if self.parent.currentProxyModel():
          self.parent.currentProxyModel().setFilterKeyColumn(self.filterColumnComboBox.currentIndex())

  def sortChanged(self):
        if self.sortCaseSensitivityCheckBox.isChecked():
            caseSensitivity = Qt.CaseSensitive
        else:
            caseSensitivity = Qt.CaseInsensitive
        if self.parent.currentProxyModel():
          self.parent.currentProxyModel().setSortCaseSensitivity(caseSensitivity)



