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
from ui.gui.configuration.conf import Conf

class NodeFilterBox(QWidget):
  """
  This class is designed to perform searches on nodes in the VFS or a part of the VFS.
  """
  def __init__(self, parent):
    QWidget.__init__(self)
    self.parent = parent

    # create the GUI for searching within the content of a node
    self.filterContentLineEdit = QLineEdit()
    self.filterContentLabel = QLabel(self.tr("Contains:"))
    self.filterContentLabel.setBuddy(self.filterContentLineEdit)
    self.filterContentLineEdit.setText("")

    # create the button used to launch the search
    self.searchButton = QPushButton(self.tr("&Search"))

    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.searchButton.clicked.connect(self.search)
    else:
      QtCore.QObject.connect(self.searchButton, SIGNAL("clicked(bool)"), self.search)

    # adding all widgets in a QGridLayout
    proxyLayout = QGridLayout()
    proxyLayout.addWidget(self.filterContentLabel, 0, 0)
    proxyLayout.addWidget(self.filterContentLineEdit, 0, 1, 1, 3)
    proxyLayout.addWidget(self.searchButton, 0, 4)

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
    dff_conf = Conf()
    if not self.filterContentLineEdit.text().isEmpty():
      search_engine = IndexSearch(str(dff_conf.index_path))
      qquery = str(self.filterContentLineEdit.text())
      qquery = qquery.lstrip()
      search_engine.exec_query(qquery, "")

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
