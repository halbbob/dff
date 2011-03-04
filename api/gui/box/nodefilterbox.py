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
from PyQt4.QtGui import QWidget, QLineEdit, QLabel, QGridLayout, QPushButton, QCheckBox, QFileDialog
from api.index.libindex import *

class NodeFilterBox(QWidget):
  """
  This class is designed to perform searches on nodes in the VFS or a part of the VFS.
  """
  def __init__(self, parent):
    QWidget.__init__(self)
    self.parent = parent
    # create GUI for filtering node by names
    self.caseSensitivity = QCheckBox(self.tr("Case sensitivity"))
    self.recurse = QCheckBox(self.tr("Search recursively"))
    self.quickSearch = QCheckBox(self.tr("Quick search"))
    self.quickSearch.setTristate(False)
    self.quickSearch.setChecked(0)

    self.filterPatternLineEdit = QLineEdit()
    self.filterPatternLabel = QLabel(self.tr("Pattern:"))
    self.filterPatternLabel.setEnabled(True)
    self.filterPatternLineEdit.setEnabled(True)
    self.filterPatternLabel.setBuddy(self.filterPatternLineEdit)
    self.filterPatternLineEdit.setText("")

    # create the GUI for searching within the content of a node
    self.filterContentLineEdit = QLineEdit()
    self.filterContentLabel = QLabel(self.tr("Contains:"))
    self.filterContentLabel.setBuddy(self.filterContentLineEdit)
    self.filterContentLineEdit.setText("")

    # widgets to load a dictionnary
    self.dictLabel = QLabel(self.tr("Dictionnary:"))
    self.dictionnary = QLineEdit()
    self.dictionnary.setText("")
    self.openDict = QPushButton(self.tr("Browse"))

    self.namesDictLabel = QLabel(self.tr("Name list:"))
    self.namesDictionnary = QLineEdit()
    self.namesDictionnary.setText("")
    self.openDictNames = QPushButton(self.tr("Browse"))

    # create the button used to launch the search
    self.searchButton = QPushButton(self.tr("&Search"))

    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.filterPatternLineEdit.textChanged.connect(self.filterRegExpChanged)
      self.searchButton.clicked.connect(self.search)
      self.quickSearch.stateChanged.connect(self.quickSearchStateChanged)
      self.openDict.clicked.connect(self.openDictionary)
      self.openDictNames.clicked.connect(self.openNamesDictionary)
    else:
      QtCore.QObject.connect(self.filterPatternLineEdit, SIGNAL("textChanged(QString)"), self.filterRegExpChanged)
      QtCore.QObject.connect(self.searchButton, SIGNAL("clicked(bool)"), self.search)
      QtCore.QObject.connect(self.openDict, SIGNAL("clicked(bool)"), self.openDictionary)
      QtCore.QObject.connect(self.quickSearch, SIGNAL("stateChanged(int)"), self.quickSearchStateChanged)
      QtCore.QObject.connect(self.openDictNames, SIGNAL("clicked(bool)"), self.openNamesDictionary)

    # adding all widgets in a QGridLayout
    proxyLayout = QGridLayout()
    proxyLayout.addWidget(self.filterPatternLabel, 0, 0)
    proxyLayout.addWidget(self.filterPatternLineEdit, 0, 1, 1, 3)
    proxyLayout.addWidget(self.namesDictLabel, 0, 4)
    proxyLayout.addWidget(self.namesDictionnary, 0, 5)
    proxyLayout.addWidget(self.openDictNames, 0, 6)

    proxyLayout.addWidget(self.filterContentLabel, 1, 0)
    proxyLayout.addWidget(self.filterContentLineEdit, 1, 1, 1, 3)
    proxyLayout.addWidget(self.dictLabel, 1, 4)
    proxyLayout.addWidget(self.dictionnary, 1, 5)
    proxyLayout.addWidget(self.openDict, 1, 6)

    proxyLayout.addWidget(self.caseSensitivity, 2, 0)
    proxyLayout.addWidget(self.quickSearch, 2, 1)
    proxyLayout.addWidget(self.recurse, 2, 2)

    proxyLayout.addWidget(self.searchButton, 2, 6)

    # set the QGridLayout in the current widget and make it visible
    self.setLayout(proxyLayout)
    self.setVisible(False)

  def filterRegExpChanged(self):
    if self.quickSearch.isChecked():
      if self.caseSensitivity.isChecked():
        caseSensitivity = Qt.CaseSensitive
      else:
        caseSensitivity = Qt.CaseInsensitive
      regExp = QRegExp(self.filterPatternLineEdit.text(), caseSensitivity)
      regExp.setPatternSyntax(QRegExp.RegExp)
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

  def search(self, changed):
    if not self.filterContentLineEdit.text().isEmpty():
      search_engine = IndexSearch(".")
      qquery = str(self.filterContentLineEdit.text())
      qquery = qquery.lstrip()
      search_engine.exec_query(qquery, "")
    elif not self.dictionnary.text().isEmpty():
      print "to be done"

  def openDictionary(self, changed):
    dialog = QFileDialog()
    dialog.exec_()
    path = str(dialog.selectedFiles()[0])
    self.dictionnary.setText(path)

  def quickSearchStateChanged(self, state):
    self.changeWidgetState(state)
    if not self.quickSearch.isChecked():
      if self.parent.currentProxyModel():
        self.parent.currentProxyModel().setFilterRegExp(QRegExp(""))
    else:
      self.filterRegExpChanged()

  def openNamesDictionary(self, changed):
    dialog = QFileDialog()
    dialog.exec_()
    path = str(dialog.selectedFiles()[0])
    self.namesDictionnary.setText(path)

  def changeWidgetState(self, state):
    self.dictionnary.setEnabled(not state)
    self.dictLabel.setEnabled(not state)
    self.filterContentLineEdit.setEnabled(not state)
    self.filterContentLabel.setEnabled(not state)
    self.openDict.setEnabled(not state)
    self.namesDictLabel.setEnabled(not state)
    self.namesDictionnary.setEnabled(not state)
    self.openDictNames.setEnabled(not state)
    self.searchButton.setEnabled(not state)
