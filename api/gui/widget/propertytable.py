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
#  Solal Jacob <solal.jacob@digital-forensic.org>
#

from PyQt4.QtCore import Qt, QString
from PyQt4.QtGui import QTableWidget, QTableWidgetItem, QHeaderView 

class PropertyTable(QTableWidget):
  def __init__(self, parent):
    QTableWidget.__init__(self)
    self.setHorizontalHeaderLabels(["Attribute","Value"])
    self.setShowGrid(False)

  def fill(self, node):
    self.clear()
    if self.isVisible():
      fsobj = node.fsobj()
      fsobjname = ""
      if fsobj != None:
        fsobjname = fsobj.name()
      table = { "name" : str(node.name()) , "module" : str(fsobjname), "size" : str(node.size()) }
      for key in node.attr.smap:
	table[key] = node.attr.smap[key]
      for key in node.attr.imap:
	table[key]  = str(node.attr.imap[key])
      for key in node.attr.time:
        table[key] = str(node.attr.time[key].get_time())

      self.setRowCount(len(table))
      self.setColumnCount(2)

      hHeader = self.horizontalHeader()
      hHeader.setStretchLastSection(True)
      hHeader.setResizeMode(QHeaderView.ResizeToContents)
      hHeader.setSortIndicator(1, 1)
      hHeader.setSortIndicatorShown(True)

      vHeader = self.verticalHeader().hide()

      self.sortByColumn(1) 
      self.setSortingEnabled(True)
      count = 0
      for key in table:
        item0 = QTableWidgetItem(QString(key))
        item0.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)	
        item1 = QTableWidgetItem(QString(table[key]))
        item1.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)	
        self.setItem(count, 0, item0)
        self.setItem(count, 1, item1)
        count += 1
      self.setHorizontalHeaderLabels(["Attribute","Value"])
      self.resizeColumnsToContents()   
