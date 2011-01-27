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

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *

from ui.gui.resources.ui_nodefilterbox import Ui_FindFile

class NodeFilterBox(QGroupBox, Ui_FindFile):
  def __init__(self, parent):
    QGroupBox.__init__(self)
    self.setupUi(self)
    
    self.parent = parent

    self.filterSyntaxComboBox.setItemData(0, QVariant(QtCore.QRegExp.RegExp))
    self.filterSyntaxComboBox.setItemData(2, QVariant(QtCore.QRegExp.Wildcard))
    self.filterSyntaxComboBox.setItemData(1, QVariant(QtCore.QRegExp.FixedString))

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

  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.retranslateUi(self)
    else:
      QGroupBox.changeEvent(self, event)


