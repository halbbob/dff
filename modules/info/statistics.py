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

from api.vfs import *
from api.magic.filetype import *
from api.module.script import *
from api.module.module import *

from PyQt4 import QtCore, QtGui
from PyQt4.QtGui import QWidget
from PyQt4.QtCore import Qt

from chart.chart import PieView

import random

class STATCHART(QWidget):
  def __init__(self):
    #super(QWidget, self).__init__()
    QWidget.__init__(self)
    self.setupModel()
    self.setupViews()

                   
  def setupModel(self):
    self.model = QtGui.QStandardItemModel(8, 2, self)
    self.model.setHeaderData(0, QtCore.Qt.Horizontal, QtCore.QVariant("Label"))
    self.model.setHeaderData(1, QtCore.Qt.Horizontal, QtCore.QVariant("Quantity"))


  def setupViews(self):
    self.vbox = QtGui.QVBoxLayout()
    self.setLayout(self.vbox)
    splitter = QtGui.QSplitter()
    table = QtGui.QTableView()
    self.pieChart = PieView()
    splitter.addWidget(table)
    splitter.addWidget(self.pieChart)
    splitter.setStretchFactor(0, 0)
    splitter.setStretchFactor(1, 1)
    
    table.setModel(self.model)
    self.pieChart.setModel(self.model)
    
    self.selectionModel = QtGui.QItemSelectionModel(self.model)
    table.setSelectionModel(self.selectionModel)
    self.pieChart.setSelectionModel(self.selectionModel)
    
    table.horizontalHeader().setStretchLastSection(True)
    self.vbox.addWidget(splitter)


  def decode(self, typestat):
    self.model.removeRows(0, self.model.rowCount(QtCore.QModelIndex()),
                          QtCore.QModelIndex())

    row = 0
    i = 0
    for mtype, count in typestat.iteritems():
      color = random.randint(0, 0xffffffff)
      self.model.insertRows(row, 1, QtCore.QModelIndex())

      self.model.setData(self.model.index(row, 0, QtCore.QModelIndex()),
                         QtCore.QVariant(mtype))
      self.model.setData(self.model.index(row, 1, QtCore.QModelIndex()),
                         QtCore.QVariant(float(count)))
      self.model.setData(self.model.index(row, 0, QtCore.QModelIndex()),
                         QtCore.QVariant(QtGui.QColor(color)),
                         QtCore.Qt.DecorationRole)
      row += 1


class STATISTICS(Script, QWidget):
  def __init__(self):
    Script.__init__(self, "statistics")
    self.vfs = vfs.vfs()
    self.ft = FILETYPE()


  def c_display(self):
    buff = ""
    for mtype, count in self.typestat.iteritems():
      buff += mtype + ": " + str(count) + "\n"
    return buff


  def g_display(self):
    QWidget.__init__(self)
    self.chart = STATCHART()
    self.vbox = QtGui.QVBoxLayout()
    self.setLayout(self.vbox)
    self.vbox.addWidget(self.chart)
    #STATCHART.__init__(self)
    self.chart.decode(self.typestat)


  def updateWidget(self):
    pass


  def start(self, args):
    self.typestat = {}
    node = args.get_node("parent")
    if node.size() > 0:
      self.addEntry(node)
    if node.hasChildren():
      self.getstat(node.children())
    for mtype, count in self.typestat.iteritems():
      self.res.add_const(mtype, count)


  def addEntry(self, node):
    res = self.ft.filetype(node)
    mtype = res["mime-type"]
    idx = mtype.find("; ")
    if idx != -1:
      mtype = mtype[:idx]
    if mtype not in self.typestat:
      self.typestat[mtype] = 1
    else:
      self.typestat[mtype] += 1


  def getstat(self, lnodes):
    folders = []
    for node in lnodes:
      if node.size() > 0:
        self.addEntry(node)
      if node.hasChildren():
        folders.append(node)
    for folder in folders:
      self.getstat(folder.children())


class statistics(Module):
  """Show statistics of filetype used for a file or a directory
ex: statistics /mydump/"""
  def __init__(self):
    Module.__init__(self, "statistics", STATISTICS)
    self.conf.add('parent', 'node', False, "Directory or file to get filetype from")
    self.tags = "information"


