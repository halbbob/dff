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

import thread

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import QWidget, QLineEdit, QLabel, QGridLayout, QPushButton, QCheckBox, QFileDialog, QMessageBox, QDialog, QProgressBar

from api.vfs.libvfs import VFS
from api.index.libindex import IndexSearch, Index

from ui.gui.resources.ui_node_f_box import Ui_NodeFBox
from ui.gui.resources.ui_advance_search import Ui_AdvanceSearch
from ui.conf import Conf

from ui.gui.widget.modif_index import ModifIndex

try:
  from api.index.libindex import *
  IndexerFound = True
except ImportError:
  IndexerFound = False
from ui.conf import Conf

class AdvSearch(QDialog, Ui_AdvanceSearch):
  def __init__(self, parent):
    super(QDialog, self).__init__()
    self.parent = parent
    self.setupUi(self)
    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.resetForm.clicked.connect(self.reset_form)
    else:
      QtCore.QObject.connect(self.resetForm, SIGNAL("clicked(bool)"), self.reset_form)

  def reset_form(self, changed):
    self.allWords.setText("")
    self.noneWord.setText("")
    self.oneWord.setText("")

class NodeFilterBox(QWidget, Ui_NodeFBox):
  """
  This class is designed to perform searches on nodes in the VFS or a part of the VFS.
  """
  def __init__(self, parent, model):
    QWidget.__init__(self)
    Ui_NodeFBox.__init__(parent)
    self.parent = parent
    self.setupUi(self)
    self.model = model
    self.translation()
    self.opt = ModifIndex(self, model)

    self.adv = AdvSearch(self)

    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.search.clicked.connect(self.searching)
      self.notIndexed.linkActivated.connect(self.index_opt2)
      self.indexOpt.clicked.connect(self.explain_this_odd_behavior)
      self.advancedSearch.clicked.connect(self.adv_search)
    else:
      QtCore.QObject.connect(self.search, SIGNAL("clicked(bool)"), self.searching)
      QtCore.QObject.connect(self.index_opt, SIGNAL("clicked(bool)"), self.explain_this_odd_behavior)
      QtCore.QObject.connect(self.notIndexed, SIGNAL("linkActivated()"), self.index_opt2)
      QtCore.QObject.connect(self.advancedSearch, SIGNAL("clicked(bool)"), self.adv_search)

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

      # delete doc from index (if any stuff are to be deleted)
      for i in self.opt.un_index:
        recurse = self.opt.indexed_items[long(i)]
        node = VFS.Get().getNodeFromPointer(i)
        if recurse == True:
          tmp = node.children()
          for j in tmp:
            IndexSearch.deleteDoc(str(j.absolute()).lower(), str(index_path).lower())
        else:
          self.deleteRecurse(node, index, index_path)
        self.opt.indexed_items.pop(i)

      # adding new selected nodes in index
      for i in self.opt.tmp_indexed_items:
        node = VFS.Get().getNodeFromPointer(i)
        self.opt.indexed_items[i] = self.opt.tmp_indexed_items[i]

        # only index current node content
        if self.opt.indexed_items[i] == True:
          tmp = node.children()
          for ii in tmp:
            index.indexData(ii)
        else: #index recursively
          self.recurseNode(node, index)
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
    ret = self.adv.exec_()
    if ret == QDialog.Accepted:
      all_word = str(self.adv.allWords.text())
      none_word = str(self.adv.noneWord.text())
      one_word = str(self.adv.oneWord.text())

      # LOL
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
      try:
        # testing shit
        useless = self.opt.indexed_items[long(self.vfs_model.rootItem.this)]

        # prepare stuff to fo the query
        conf = Conf()
        index_path = conf.index_path # get path to the index
        search_engine = IndexSearch(index_path)
        qquery = str(self.searchClause.text())

        # strip the query to remove useless char
        qquery = qquery.lstrip()

        # exec the query
        search_engine.exec_query(qquery, "")
      except KeyError:
        # if the key is not found that means that the current node is not indexed
        self.notIndexed.setText("<font color='red'>" + self.msg_not_indexed \
                                  + "</font> <a href=\"\#\">" + self.msg_not_indexed2 \
                                  + "</a>")

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
