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
#  Romain Bertholon <rbe@digital-forensic.org>
# 

from PyQt4 import QtCore, QtGui

from PyQt4.QtGui import QWidget, QDateTimeEdit, QLineEdit, QHBoxLayout, QLabel, QPushButton, QMessageBox, QListWidget, QTableWidget, QTableWidgetItem, QAbstractItemView, QIcon
from PyQt4.QtCore import QVariant, SIGNAL, QThread, Qt, QFile, QIODevice, QStringList

from api.events.libevents import EventHandler, event
from api.search.find import Filters

from api.gui.widget.SearchNodeBrowser import SearchNodeBrowser

from api.gui.model.vfsitemmodel import ListNodeModel
from api.gui.widget.propertytable import PropertyTable

from api.vfs.libvfs import VFS, Node, VLink
from api.vfs.vfs import vfs
from api.types.libtypes import Variant, typeId

from api.gui.widget.build_search_clause  import BuildSearchClause
from ui.gui.resources.ui_search import Ui_SearchTab
from ui.gui.resources.ui_search_clause import Ui_SearchClause

class SearchClause(Ui_SearchClause, QWidget):
  def __init__(self, parent = None):
    super(QWidget, self).__init__(parent)
    self.setupUi(self)

    self.parent = parent

    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.delete_clause.clicked.connect(self.removeClauseFromWidget)
    else:
      QtCore.QObject.connect(self.delete_clause, SIGNAL("clicked(bool)"), self.removeClauseFromWidget)

  def removeClauseFromWidget(self, changed):
    self.parent.advancedOptions.removeWidget(self)
    self.parent.clause_list.remove(self)
    self.close()
    self.parent.rebuildQuery()

class FilterThread(QThread):
  def __init__(self, parent=None):
    QThread.__init__(self)
    self.__parent = parent
    self.filters = Filters()
    self.model = None

  def setContext(self, clauses, rootnode, model=None):
    if model:
      self.model = model
      self.connect(self, SIGNAL("started"), self.model.launch_search)
      self.connect(self, SIGNAL("finished"), self.model.end_search)
      self.connect(self.model, SIGNAL("stop_search()"), self.quit)
    elif self.__parent:
      self.connect(self.__parent, SIGNAL("stop_search()"), self.quit)
    self.filters.setRootNode(rootnode)
    self.filters.compile(clauses)

  def run(self):
    self.emit(SIGNAL("started"))
    matches = self.filters.process()
    self.emit(SIGNAL("finished"))
    self.model = None

  def quit(self):
    e = event()
    e.thisown = False
    e.type = 0
    e.value = None
    self.filters.Event(e)
    self.emit(SIGNAL("finished"))
    QThread.quit(self)

class AdvSearch(QWidget, Ui_SearchTab, EventHandler):
  def __init__(self, parent):
    super(QWidget, self).__init__()
    EventHandler.__init__(self)
    self.filterThread = FilterThread(self)
    self.filterThread.filters.connection(self)
    self.parent = parent
    self.vfs = vfs()
    self.name = "Advanced search"
    self.setupUi(self)

    self.clause_list = []
    self.operator_list = []

    self.completeClause.setText("")
    self.__totalnodes = 0
    self.__totalhits = 0
    self.__processednodes = 0

    self.icon = ":search.png"
    self.translation()
    self.attrsTree.addWidget(PropertyTable(None))

    self.model = ListNodeModel(self)
    self.searchResults = SearchNodeBrowser(self)
    self.nodeBrowserLayout.addWidget(self.searchResults)
    self.node_name = QLineEdit()
    self.node_name.setReadOnly(True)
    self.nodeBrowserLayout.addWidget(self.node_name)

    self.searchResults.addTableView()
    self.searchResults.tableView.setModel(self.model)
    self.connect(self.searchResults.tableView, SIGNAL("nodeClicked"), self.change_node_name)
    
    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.launchSearchButton.clicked.connect(self.launchSearch)
      self.stopSearchButton.clicked.connect(self.stopSearch)
      self.exportButton.clicked.connect(self.export)
    else:
      QtCore.QObject.connect(self.launchSearchButton, SIGNAL("clicked(bool)"), self.launchSearch)
      QtCore.QObject.connect(self.stopSearchButton, SIGNAL("clicked(bool)"), self.stopSearch)
      QtCore.QObject.connect(self.exportButton, SIGNAL("clicked(bool)"), self.export)

    self.typeName.addItem("Fixed string", QVariant("f"))
    self.typeName.addItem("Wildcard", QVariant("w"))
    self.stopSearchButton.hide()
    self.exportButton.setEnabled(False)
    self.addedOpt = []

    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.addOption.clicked.connect(self.addSearchOptions)
    else:
      QtCore.QObject.connect(self.addOption, SIGNAL("clicked(bool)"), self.addSearchOptions)

    self.connect(self, SIGNAL("TotalNodes"), self.searchBar.setMaximum)
    self.connect(self, SIGNAL("CountNodes"), self.searchBar.setValue)
    self.connect(self.filterThread, SIGNAL("finished"), self.searchFinished)
    QtCore.QObject.connect(self.selectAll, SIGNAL("stateChanged(int)"), self.select_all)

  def addSearchOptions(self, changed):
    clause = {}
    clause_box = BuildSearchClause()
    ret = clause_box.exec_()
    if ret:
      idx = self.typeName.currentIndex()
      data_type = self.typeName.itemData(idx)
      
      for i in range(0, clause_box.advancedOptions.count()):
        widget = clause_box.advancedOptions.itemAt(i).widget()
        if not len(widget.edit.text()):
          continue
        try:
          if len(clause[widget.edit.field]):
            clause[widget.edit.field] += (widget.edit.operator() + " " + widget.edit.field)
            clause[widget.edit.field] += (widget.edit.text())
        except KeyError:
          clause[widget.edit.field] = (widget.edit.text())

      table_clause_widget = SearchClause(self)
      table_clause_widget.clause_widget.setShowGrid(False)
      table_clause_widget.clause_widget.verticalHeader().hide()
      table_clause_widget.clause_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
      table_clause_widget.clause_widget.setAlternatingRowColors(True)
      table_clause_widget.clause_widget.insertColumn(0)
      table_clause_widget.clause_widget.insertColumn(1)
      table_clause_widget.clause_widget.setHorizontalHeaderItem(0, QTableWidgetItem("Field"))
      table_clause_widget.clause_widget.setHorizontalHeaderItem(1, QTableWidgetItem("Clause"))
      table_clause_widget.clause_widget.horizontalHeader().setStretchLastSection(True)

      nb_line = 0
      text = ""

      if not self.nameContain.text().isEmpty():
        print "name : " + self.nameContain.text()
        text += ("(name ('" + self.nameContain.text() + "'")
        if not self.caseSensitiveName.isChecked():
          text += ",i)"
        else:
          text += ")"
        if len(self.clause_list):
          text += " or "

      if self.completeClause.text() == "":
        text += "( "
      else:
        text = self.completeClause.text()
        text += " or ( "
      for i in clause:
        table_clause_widget.clause_widget.insertRow(table_clause_widget.clause_widget.rowCount())
        table_clause_widget.clause_widget.setItem(table_clause_widget.clause_widget.rowCount() - 1, 0, QTableWidgetItem(i))
        table_clause_widget.clause_widget.setItem(table_clause_widget.clause_widget.rowCount() - 1, 1, QTableWidgetItem(clause[i]))
        table_clause_widget.clause_widget.resizeRowToContents(table_clause_widget.clause_widget.rowCount() - 1)
        if nb_line == 0:
          text += ("(" + i + " " + clause[i] + ")")
        else:
          text += (" or (" + i + " " +  clause[i] + ")")
        nb_line = nb_line + 1
      text += ")"

      if nb_line:
        if len(self.clause_list) != 0:
          if QtCore.PYQT_VERSION_STR >= "4.5.0":
            table_clause_widget.and_clause.clicked.connect(self.rebuildQuery)
            table_clause_widget.or_clause.clicked.connect(self.rebuildQuery)
          else:
            QtCore.QObject.connect( table_clause_widget.and_clause, SIGNAL("clicked(bool)"), self.rebuildQuery)
            QtCore.QObject.connect( table_clause_widget.or_clause, SIGNAL("clicked(bool)"), self.rebuildQuery)
        else:
          table_clause_widget.or_clause.hide()
          table_clause_widget.and_clause.hide()
        table_clause_widget.clause_widget.setMaximumHeight(nb_line * 25 + 50)
        self.completeClause.setText(text)
        self.advancedOptions.addWidget(table_clause_widget, self.advancedOptions.rowCount(), 0)
        self.clause_list.append(table_clause_widget)

  def rebuildQuery(self):
    text = ""
    if self.nameContain.text() != "":
      print self.nameContain.text()
      text += ("(name " + self.nameContain.text() + ")")
      if len(self.clause_list):
        text += " or "

    for i in range(0, len(self.clause_list)):
      if i == 0:
        text = "("
        self.clause_list[i].or_clause.hide()
        self.clause_list[i].and_clause.hide()
      else:
        if self.clause_list[i].or_clause.isChecked():
          text += " or ("
        else:
          text += " and ("
      clause_widget = self.clause_list[i]
      for j in range(0, clause_widget.clause_widget.rowCount()):
        if j != 0:
          text += " or " 
        text += "("
        text += (clause_widget.clause_widget.item(j, 0).text() + " ")
        text += clause_widget.clause_widget.item(j, 1).text()
        text += ")"
      text += ")"
    self.completeClause.setText(text)

  def select_all(self, state):
    checked = Qt.Unchecked
    if state == Qt.Checked:
      checked = Qt.Checked
    nb_row = self.model.rowCount()
    self.model.emit(SIGNAL("layoutAboutToBeChanged()"))
    for i in range(0, nb_row):
      index = self.model.index(i, 0)
      if not index.isValid():
        continue
      self.model.setData(index, checked, Qt.CheckStateRole)
    self.model.emit(SIGNAL("layoutChanged()"))

  def change_node_name(self, button, node):
    self.node_name.setText(node.absolute())

  def Event(self, e):
    if e.type == 0x200:
      self.__totalnodes = e.value.value()
      self.emit(SIGNAL("TotalNodes"), int(e.value.value()))
    if e.type == 0x201:
      self.__processednodes += 1
      self.emit(SIGNAL("CountNodes"), int(e.value.value()))
    if e.type == 0x202:
      self.__totalhits += 1
      self.totalHits.setText(str(self.__totalhits) + "/" + str(self.__totalnodes) + " " + self.tr("match(s)"))
      self.emit(SIGNAL("NodeMatched"), e)

  def searchFinished(self):
    if self.__totalhits:
      self.exportButton.setEnabled(True)
    self.stopSearchButton.hide()
    self.launchSearchButton.show()

  def export(self):
    text, ok = QInputDialog.getText(self, "Advanced search", "Filter export name", QLineEdit.Normal, "") 
    if ok and text != "":
      siNode = self.vfs.getnode("/Searched items")
      filtersNode = Node(str(text), 0, siNode, None)
      filtersNode.__disown__()
      filtersNode.setDir()
      e = event()
      e.thisown = False
      vnode = Variant(filtersNode)
      vnode.thisown = False
      e.value = vnode
      VFS.Get().notify(e)
      nb_row = self.model.rowCount()
      for i in range(0, nb_row):
        index = self.model.index(i, 0)
        if not index.isValid():
          continue
        data = self.model.data(index, Qt.CheckStateRole)
        if data == Qt.Checked or data == Qt.PartiallyChecked:
          n = VFS.Get().getNodeFromPointer(long(index.internalId()))
          l = VLink(n, filtersNode)
          l.__disown__()
    else:
      box = QMessageBox(QMessageBox.Warning, "Error", "Error node already exists", QMessageBox.NoButton, self)
      box.exec_()

  def stopSearch(self, changed):
    self.emit(SIGNAL("stop_search()"))

  def launchSearch(self, changed):
    clause = {}

    self.emit(SIGNAL("NewSearch"))
    self.__totalhits = 0
    self.__processednodes = 0
    self.totalHits.setText("0 " + self.tr(" match(s)"))
    self.exportButton.setEnabled(False)
    idx = self.typeName.currentIndex()
    data_type = self.typeName.itemData(idx)
    if not self.nameContain.text().isEmpty():
      search = str(data_type.toString())
      search += ("(\'" + str(self.nameContain.text()) + "\'")
      if not self.caseSensitiveName.isChecked():
        search += ",i)"
      else:
        search += ")"
      clause["name"] = search

    print self.completeClause.text()

    self.filterThread.setContext(clause, self.vfs.getnode(str(self.path.text())))
    self.searchBar.show()
    self.launchSearchButton.hide()
    self.stopSearchButton.show()
    self.filterThread.start()

  def showMoreOptions(self, changed):
    pass

  def setCurrentNode(self, path):
    self.search_in_node = path

  def translation(self):
    pass
