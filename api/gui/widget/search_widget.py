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

from PyQt4.QtGui import QWidget, QDateTimeEdit, QLineEdit, QHBoxLayout, QLabel, QPushButton, QMessageBox, QInputDialog, QIcon
from PyQt4.QtCore import QVariant, SIGNAL, QThread

from api.events.libevents import EventHandler, event
from api.search.find import Filters
from api.gui.widget.SearchNodeBrowser import SearchNodeBrowser
from api.gui.model.vfsitemmodel import ListNodeModel
from api.gui.widget.propertytable import PropertyTable
from api.vfs.libvfs import VFS, Node, VLink
from api.vfs.vfs import vfs
from api.types.libtypes import Variant, typeId

from ui.gui.resources.ui_search import Ui_SearchTab
from ui.gui.resources.ui_search_size import Ui_SearchSize
from ui.gui.resources.ui_search_empty import Ui_SearchEmpty
from ui.gui.resources.ui_search_date import Ui_SearchDate
from ui.gui.resources.ui_SearchStr import Ui_SearchStr

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


class SearchStr(Ui_SearchStr, QWidget):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.no = False
    self.field = "data"

    self.type.addItem("Fixed string", QVariant("f"))
    self.type.addItem("Wildcard", QVariant("w"))
    self.type.addItem("Fuzzy", QVariant("fz"))
    self.type.addItem("Reg exp", QVariant("r"))

  def setNo(self, no):
    self.no = no

  def operator(self):
    return " and "

  def text(self):
    if self.name.text().isEmpty():
      return ""
    search = ""
    if self.no:
      search += "not "

    idx = self.type.currentIndex()
    data_type = self.type.itemData(idx)
    search += str(data_type.toString())

    search += ("(\'" + str(self.name.text()) + "\'")
    if not self.caseSensitive.isChecked():
      search += ",i)"
    else:
      search += ")"
    return str(search)

class SearchD(QWidget, Ui_SearchDate):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.no = False
    self.field = "time"

  def setNo(self, no):
    self.no = no

  def operator(self):
    return " and "

  def text(self):
    prefix = ""
    if self.no:
      prefix += " <= "
    else:
      prefix += " >= "
    date_time = self.dateTimeEdit.dateTime()
    if self.date_str.isChecked():
      return prefix + str(date_time.toString("yyyy-MM-ddThh:mm:ss"))
    return prefix + "ts(" + str(date_time.toTime_t()) + ")"

class SearchS(QWidget, Ui_SearchSize):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.translation()

    self.no = False
    self.field = "size"

  def setNo(self, no):
    self.no = no

  def operator(self):
    return " or "

  def text(self):
    prefix = ""
    if self.no:
      prefix += " <= "
    else:
      prefix += " >= "

    print "unit : " + str(self.unit.currentText())

    if self.unit.currentText() == self.kiloTr:
      return prefix + str(self.size.value() * 1024)
    if self.unit.currentText() == self.megaTr:
      return prefix + str(self.size.value() * 1024 * 1024)
    if self.unit.currentText() == self.gigaTr:
      return prefix + str(self.size.value() * 1024 * 1024 * 1024)
    return prefix + str(self.size.value())

  def translation(self):
    self.kiloTr = self.tr("Kilo bytes")
    self.megaTr = self.tr("Mega bytes")
    self.gigaTr = self.tr("Giga bytes")

class OptWidget(QWidget):
  def __init__(self, parent, w_type = 0):
    super(QWidget, self).__init__()
    self.layout = QHBoxLayout(self)
    self.type = w_type
    self.translation()

    self.funcMapper = {typeId.Char: SearchStr,
                       typeId.Int16: SearchS,
                       typeId.UInt16: SearchS,
                       typeId.Int32: SearchS,
                       typeId.UInt32: SearchS,
                       typeId.Int64: SearchS,
                       typeId.UInt64: SearchS,
                       typeId.String: SearchStr,
                       typeId.CArray: SearchStr,
                       typeId.Node: SearchStr,
                       typeId.Path: SearchStr,
                       typeId.VTime: SearchD,

                       # MEGALOL - NEED TO BE CHANGED
                       typeId.Char + 100: SearchStr,
                       typeId.Int16 + 100: SearchS,
                       typeId.UInt16 + 100: SearchS,
                       typeId.Int32 + 100: SearchS,
                       typeId.UInt32 + 100: SearchS,
                       typeId.Int64  + 100: SearchS,
                       typeId.UInt64 + 100: SearchS,
                       typeId.String + 100: SearchStr,
                       typeId.CArray + 100: SearchStr,
                       typeId.Node + 100: SearchStr,
                       typeId.Path + 100: SearchStr,
                       typeId.VTime + 100: SearchD}

    self.parent = parent
    self.id = -1
    self.label = QLabel()
    self.layout.addWidget(self.label)
    self.edit = self.value(w_type)
    self.layout.addWidget(self.edit)
    self.button = QPushButton(QIcon(":remove.png"), "", self)
    self.button.setToolTip(self.delTr)
    self.layout.addWidget(self.button)
    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.button.clicked.connect(self.removeOption)
    else:
      QtCore.QObject.connect(self.button, SIGNAL("clicked(bool)"), self.removeOption)
    
  def removeOption(self, changed):
    text = self.label.text()
    self.parent.optionList.addItem(text, self.type)
    self.parent.addedOpt.remove(self)
    self.label.hide()
    self.edit.hide()
    self.button.hide()
    self.parent.optionList.setEnabled(True)
    self.parent.addOption.setEnabled(True)
    self.parent.advancedOptions.removeWidget(self)

  def value(self, valType):
    func = self.funcMapper[valType]
    if func != None:
      return func()
    return QWidget()

  def translation(self):
    self.delTr = self.tr("Remove")

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
    #self.searchResults.horizontalHeader().setStretchLastSection(True)
    self.connect(self.searchResults.tableView, SIGNAL("nodeClicked"), self.change_node_name)
    

    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.launchSearchButton.clicked.connect(self.launchSearch)
      self.stopSearchButton.clicked.connect(self.stopSearch)
      self.exportButton.clicked.connect(self.export)
    else:
      QtCore.QObject.connect(self.launchSearchButton, SIGNAL("clicked(bool)"), self.launchSearch)
      QtCore.QObject.connect(self.stopSearchButton, SIGNAL("clicked(bool)"), self.stopSearch)
      QtCore.QObject.connect(self.exportButton, SIGNAL("clicked(bool)"), self.export)

    self.optionList.addItem(self.textTr, QVariant(typeId.String))
    self.optionList.addItem(self.notNameTr, QVariant(typeId.String + 100))
    self.optionList.addItem(self.notContains, QVariant(typeId.String + 100))
    self.optionList.addItem(self.sizeMinTr, QVariant(typeId.UInt64))
    self.optionList.addItem(self.sizeMaxTr, QVariant(typeId.UInt64 + 100))
    self.optionList.addItem(self.dateMaxTr, QVariant(typeId.VTime + 100))
    self.optionList.addItem(self.dateMinTr, QVariant(typeId.VTime))

    self.typeName.addItem("Fixed string", QVariant("f"))
    self.typeName.addItem("Wildcard", QVariant("w"))
    self.typeName.addItem("Fuzzy", QVariant("fz"))
    self.typeName.addItem("Reg exp", QVariant("re"))

    self.optionList.hide()
    self.addOption.hide()
    self.advOptBox.hide()
    self.stopSearchButton.hide()

    self.exportButton.setEnabled(False)

    self.addedOpt = []

    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.moreOptionsButton.clicked.connect(self.showMoreOptions)
      self.addOption.clicked.connect(self.addSearchOptions)
    else:
      QtCore.QObject.connect(self.moreOptionsButton, SIGNAL("clicked(bool)"), self.showMoreOption)
      QtCore.QObject.connect(self.addOption, SIGNAL("clicked(bool)"), self.addSearchOptions)

    self.connect(self, SIGNAL("TotalNodes"), self.searchBar.setMaximum)
    self.connect(self, SIGNAL("CountNodes"), self.searchBar.setValue)
    self.connect(self.filterThread, SIGNAL("finished"), self.searchFinished)

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
    #self.searchBar.hide()
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
      for node in self.model.node_list:
        n = VFS.Get().getNodeFromPointer(int(node))
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

    for i in range(0, self.advancedOptions.count()):
      widget = self.advancedOptions.itemAt(i).widget()
      if not len(widget.edit.text()):
        continue
      try:
        if len(clause[widget.edit.field]):
          clause[widget.edit.field] += widget.edit.operator()
      except KeyError:
        clause[widget.edit.field] = ""
      clause[widget.edit.field] += (widget.edit.text())
    self.filterThread.setContext(clause, self.vfs.getnode(str(self.path.text())))
    self.searchBar.show()
    self.launchSearchButton.hide()
    self.stopSearchButton.show()
    self.filterThread.start()
    return clause


  def showMoreOptions(self, changed):
    self.optionList.setVisible(not self.optionList.isVisible())
    self.addOption.setVisible(not self.addOption.isVisible())
    self.advOptBox.setVisible(not self.advOptBox.isVisible())
    if self.moreOptionsButton.text() == "+":
      self.moreOptionsButton.setText("-")
    else:
      self.moreOptionsButton.setText("+")

  def setCurrentNode(self, path):
    self.search_in_node = path
    
  def addSearchOptions(self, changed):
    # removing from combo box
    text = self.optionList.currentText()

    if text.isEmpty():
      self.optionList.setEnabled(False)
      self.addOption.setEnabled(False)
      return
    self.optionList.setEnabled(True)
    self.addOption.setEnabled(True)

    # add a new line
    truc = self.optionList.itemData(self.optionList.currentIndex()).toInt()[0]
    widget = OptWidget(self, truc)
    if truc >= (100 + typeId.String):
      widget.edit.setNo(True)
    if text == self.notNameTr:
      widget.edit.field = "name"

    self.optionList.removeItem(self.optionList.currentIndex())

    widget.label.setText(text)
    widget.id = len(self.addedOpt)
    self.advancedOptions.addWidget(widget)
    self.addedOpt.append(widget)
    if not self.optionList.count():
      self.optionList.setEnabled(False)
      self.addOption.setEnabled(False)

  def translation(self):
    self.textTr = self.tr("Contains")
    self.notNameTr = self.tr("Name does not contain")
    self.notContains = self.tr("Does not contain")
    self.sizeMinTr = self.tr("Size at least")
    self.sizeMaxTr = self.tr("Size at most")
    self.dateMaxTr = self.tr("Date less than")
    self.dateMinTr = self.tr("Date most than")

