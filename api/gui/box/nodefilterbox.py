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
#  Romain Bertholon <rbe@digital-forensic.org>
# 

import thread

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import QWidget, QDialog

from api.vfs.vfs import vfs
from api.events.libevents import EventHandler
from api.types.libtypes import typeId
from api.search.find import Filters
from api.gui.widget.search_widget import SearchStr, SearchD, SearchS, OptWidget, AdvSearch, FilterThread

from ui.gui.resources.ui_node_f_box import Ui_NodeFBox
from ui.conf import Conf

try:
  from api.index.libindex import IndexSearch, Index
  from ui.gui.widget.modif_index import ModifIndex
  IndexerFound = True
except ImportError:
  IndexerFound = False
from ui.conf import Conf    

class NodeFilterBox(QWidget, Ui_NodeFBox, EventHandler):
  """
  This class is designed to perform searches on nodes in the VFS or a part of the VFS.
  """
  def __init__(self, parent, model):
    QWidget.__init__(self)
    Ui_NodeFBox.__init__(parent)
    EventHandler.__init__(self)
    self.parent = parent
    self.filterThread = FilterThread()
    self.filterThread.filters.connection(self)

    self.setupUi(self)
    self.model = model
    self.translation()
    if IndexerFound:
      self.opt = ModifIndex(self, model)
    self.vfs = vfs()
    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.search.clicked.connect(self.searching)
      if IndexerFound:
        self.notIndexed.linkActivated.connect(self.index_opt2)
        self.indexOpt.clicked.connect(self.explain_this_odd_behavior)
      self.advancedSearch.clicked.connect(self.adv_search)

      self.connect(self, SIGNAL("add_node"), self.parent.model.fillingList)
    else:
      QtCore.QObject.connect(self.search, SIGNAL("clicked(bool)"), self.searching)
      if IndexerFound:
        QtCore.QObject.connect(self.index_opt, SIGNAL("clicked(bool)"), self.explain_this_odd_behavior)
        QtCore.QObject.connect(self.notIndexed, SIGNAL("linkActivated()"), self.index_opt2)
      QtCore.QObject.connect(self.advancedSearch, SIGNAL("clicked(bool)"), self.adv_search)
      self.connect(self, SIGNAL("add_node"), self.parent.model.fillingList)

  def Event(self, e):
    node = e.value.value()
    if e.type == 514:
      self.emit(SIGNAL("add_node"), long(node.this))

  def index_opt2(self, url):
    self.explain_this_odd_behavior()

  def explain_this_odd_behavior(self):
    ret = self.opt.exec_()
    thread.start_new_thread(self.index_opt, (True, ret))

  def index_opt(self, changed, ret):
    # set labal to indicate that a dir is not indexed to empty
    self.notIndexed.setText("")

    conf = Conf()
    index_path = conf.index_path

    if ret == QDialog.Accepted:
      index = Index(index_path)
      index.createIndex()

      # config index
      index_c = self.opt.indexFileContent.checkState()
      index_a = self.opt.indexFileAttr.checkState()

      if index_c == Qt.Checked:
        index.setIndexContent(True)
      else:
        index.setIndexContent(False)

      if index_a == Qt.Checked:
        index.setIndexAttr(True)
      else:
       index.setIndexAttr(False)

      value = 0
      for i in self.opt.un_index:
        recurse = self.opt.indexed_items[long(i)]
        node = VFS.Get().getNodeFromPointer(i)
        for (root_dir, files, dirs) in self.vfs.walk(node, True, 1):
          value += len(files)
      
      for i in self.opt.tmp_indexed_items:
        recurse = self.opt.tmp_indexed_items[long(i)]
        node = VFS.Get().getNodeFromPointer(i)
        for (root_dir, files, dirs) in self.vfs.walk(node, True, 1):
          value += len(files)
      self.emit(SIGNAL("number_max"), value)

      # delete doc from index (if any stuff are to be deleted)
      value = 0
      for i in self.opt.un_index:
        recurse = self.opt.indexed_items[long(i)]
        node = VFS.Get().getNodeFromPointer(i)
        if recurse == True:
          tmp = node.children()
          for j in tmp:
            value += 1
            IndexSearch.deleteDoc(str(j.absolute()).lower(), str(index_path).lower())
        else:
          value += 1
          self.deleteRecurse(node, index, index_path)
        self.emit(SIGNAL("number_indexed"), value)
        self.opt.indexed_items.pop(i)

      # adding new selected nodes in index
      for i in self.opt.tmp_indexed_items:
        node = VFS.Get().getNodeFromPointer(i)
        self.opt.indexed_items[i] = self.opt.tmp_indexed_items[i]

        # only index current node content
        if self.opt.indexed_items[i] == True:
          tmp = node.children()
          for ii in tmp:
            value += 1
            index.indexData(ii)
        else: #index recursively
          value += 1
          self.recurseNode(node, index)
        self.emit(SIGNAL("number_indexed"), value)
      self.opt.tmp_indexed_items.clear()

      index.closeIndex()
      # un-activated the check box for nodes which have been recursivly indexed.
      self.hide_recurse()
      # clear the un index dict
      self.opt.un_index.clear()

  def hide_recurse(self):
    for i in range(0, self.opt.indexedItems.rowCount()):
      item = self.opt.indexedItems.item(i, 1)
      if item.data(Qt.CheckStateRole) == Qt.Checked:
        item.setFlags(Qt.NoItemFlags)

  def deleteRecurse(self, node, index, index_path):
    if not node:
      return
    if node.size() and node.isFile():
      IndexSearch.deleteDoc(str(node.absolute()), index_path)
    if node.hasChildren(): # if the node has children, get all of them
      tmp = node.children()
      for i in tmp:
        self.deleteRecurse(i, index, index_path);

  def recurseNode(self, node, index):
    if not node:
      return ;
    if node.size() and node.isFile():
      index.indexData(node);
    if node.hasChildren(): # if the node has children, get all of them
      tmp = node.children()
      for i in tmp:
        self.recurseNode(i, index);

  def adv_search(self, changed):

    # parent is an instance of NodeBrowser
    adv = AdvSearch(self)

    self.parent.parent.addSearchTab(adv)
    adv.setCurrentNode(self.parent.model.rootItem)
    adv.path.setText(adv.search_in_node.absolute())
    return

    ret = self.adv.show()
    return

    ret = self.adv.exec_()
    if ret == QDialog.Accepted:
      all_word = str(self.adv.allWords.text())
      none_word = str(self.adv.noneWord.text())
      one_word = str(self.adv.oneWord.text())

      # LOL : to avoid a weird crash. Attempting to input the "t" string to clucene results in a crash
      if all_word == "t":
        all_word = ""
      if none_word == "t":
        none_word = ""
      if one_word == "t":
        one_word = ""
      if all_word == "" and none_word == "" and one_word == "":
        return

      query = ""
      query += one_word
      none_word = none_word.lstrip()
      l = none_word.split()
      if len(l):
        for i in l:
          query += (" -" + i)
      elif none_word != "":
        query += (" -" + none_word)

      all_word = all_word.lstrip()
      l = all_word.split()
      if len(l):
        for i in l:
          query += (" AND " + i)
      elif all_word != "":
        if self.adv.allWordTitle.isChecked():
          query += (all_word)
        if self.adv.allWordContent.isChecked():
          query += (all_word)

      # prepare stuff to fo the query
      conf = Conf()
      index_path = conf.index_path # get path to the index
      search_engine = IndexSearch(index_path)
      search_engine.exec_query(query, "")

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

  def searching(self, changed):
    if not self.searchClause.text().isEmpty():
      if self.recurse.checkState() != Qt.Checked:
        self.filterThread.filters.setRecursive(False)
      else:
        self.filterThread.filters.setRecursive(True)
      clause = {}
      clause["name"] = "w(\'*" + str(self.searchClause.text()) + "*\',i)"
      print clause      
      self.filterThread.setContext(clause, self.parent.model.rootItem, self.parent.model)
      self.filterThread.start()

  def translation(self):
    self.msg_not_indexed = self.tr("This location is not indexed.")
    self.msg_not_indexed2 = self.tr("Index it ?")

  def   vfs_item_model(self, model):
    """
    Method used to access to the vfsitemmodel. It is used to know
    the current directory in which we currently are.
    """
    self.vfs_model = model
    self.connect(self.vfs_model, SIGNAL("rootPathChanged"), self.hideIndexBar)

  def   hideIndexBar(self, node):    
    self.notIndexed.setText("")
