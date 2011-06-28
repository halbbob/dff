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

from PyQt4.QtGui import QWidget, QDateTimeEdit, QLineEdit, QHBoxLayout, QLabel, QPushButton, QMessageBox, QInputDialog, QIcon, QFileDialog, QErrorMessage, QListWidget, QDialog
from PyQt4.QtCore import QVariant, SIGNAL, QThread, Qt, QFile, QIODevice, QStringList

from api.types.libtypes import Variant, typeId

from ui.gui.resources.ui_search_size import Ui_SearchSize
from ui.gui.resources.ui_search_empty import Ui_SearchEmpty
from ui.gui.resources.ui_search_date import Ui_SearchDate
from ui.gui.resources.ui_SearchStr import Ui_SearchStr
from ui.gui.resources.ui_search_dict import Ui_SearchDict
from ui.gui.resources.ui_is_file_or_folder import Ui_FileOrFolder
from ui.gui.resources.ui_is_deleted import Ui_IsDeleted
from ui.gui.resources.ui_search_mime_type import Ui_MimeType
from ui.gui.resources.ui_build_search_clause import Ui_BuildSearchClause
from ui.gui.resources.ui_edit_dict import Ui_DictListEdit
from ui.gui.resources.ui_select_mime_types import Ui_selectMimeTypes

from ui.gui.widget.SelectMimeTypes import MimeTypesTree

class SelectMimeTypes(Ui_selectMimeTypes, QDialog):
  def __init__(self, parent = None):
    super(QDialog, self).__init__()
    self.setupUi(self)
    self.translation()

    self.mime_types.setHeaderLabels([self.mimeTypeTr])

    self.mime = MimeTypesTree(self.mime_types)

  def translation(self):
    self.mimeTypeTr = self.tr("Select one or several mime-types")

class MimeType(Ui_MimeType, QWidget):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.text_t = ""
    self.field = "\"mime\""

    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.edit_mime_types.clicked.connect(self.editMimeTypes)
    else:
      QtCore.QObject.connect(self.edit_mime_types, SIGNAL("clicked(bool)"), self.editMimeTypes)
    
  def editMimeTypes(self, changed):
    edit_dialog = SelectMimeTypes()
    ret = edit_dialog.exec_()
    if QDialog.Accepted:
      root_item = edit_dialog.mime_types.invisibleRootItem()
      for i in range(0, root_item.childCount()):
        parent_item = root_item.child(i)
        for j in range(0, parent_item.childCount()):
          child_item = parent_item.child(j)
          if child_item.checkState(0) == Qt.Checked:
            self.selected_mime_types.addItem(parent_item.text(0) + "/" + child_item.text(0))

  def text(self):
    text_t = " in ["
    for i in range(0, self.selected_mime_types.count()):
      if i != 0:
        text_t += ", "
      text_t += ("\"" +  self.selected_mime_types.itemText(i) + "\"")
    text_t += "]"
    print text_t
    return text_t

class DictListEdit(Ui_DictListEdit, QDialog):
  def __init__(self, word_list, parent = None):
    super(QDialog, self).__init__()
    self.setupUi(self)
    self.word_list = word_list
    self.listWidget.addItems(self.word_list)

class SearchStr(Ui_SearchStr, QWidget):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.no = False
    self.field = "\"data\""

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

    if self.no:
      search = " != "
    else:
      search = " == "

    idx = self.type.currentIndex()
    data_type = self.type.itemData(idx)
    search += str(data_type.toString())

    search += ("(\"" + str(self.name.text()) + "\"")
    if not self.caseSensitive.isChecked():
      search += ",i)"
    else:
      search += ")"
    return str(search)

class SearchDict(QWidget, Ui_SearchDict):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.translation()
    self.word_list = []

    self.field = "\"dict\""

    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.editDictContent.clicked.connect(self.edit_dict)
      QtCore.QObject.connect(self.openDict, SIGNAL("clicked(bool)"), self.open_dict)
    else:
      QtCore.QObject.connect(self.editDictContent, SIGNAL("clicked(bool)"), self.edit_dict)
      QtCore.QObject.connect(self.openDict, SIGNAL("clicked(bool)"), self.open_dict)
    self.editDictContent.setEnabled(False)

  def edit_dict(self, changed):
    edit_dialog = DictListEdit(self.word_list)
    ret = edit_dialog.exec_()

  def open_dict(self, changed):
    """
    Open a dialog box where the user can chose wich file to load.
    """
    dialog = QFileDialog()
    ret = dialog.exec_()

    # if the user validate its choice
    if ret:
      # get te path and set it in the line edit
      path = dialog.selectedFiles()[0]
      self.pathToDict.setText(path)
      dict_file = QFile(path)
      opened = dict_file.open(QIODevice.ReadOnly)
      if not opened:
        return
      buf = dict_file.readLine()
      if len(buf):
        self.word_list.append(str(buf).rstrip('\n'))
      while buf != "":
        buf = ""
        buf = dict_file.readLine()
        if len(buf):
          self.word_list.append(str(buf).rstrip('\n'))
      dict_file.close()
      self.editDictContent.setEnabled(True)

  def text(self):
    text = "(\"" + self.pathToDict.text() + "\")"
    return text

  def translation(self):
    self.errTr = "Cannot read the file."

class SearchD(QWidget, Ui_SearchDate):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.no = False
    self.field = "\"time\""

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
      return prefix + str(date_time.toString("yyyy-MM-dd hh:mm:ss"))
    return prefix + "ts(" + str(date_time.toTime_t()) + ")"

class SearchS(QWidget, Ui_SearchSize):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.translation()

    self.no = False
    self.field = "\"size\""

  def setNo(self, no):
    self.no = no

  def operator(self):
    return " and "

  def text(self):
    prefix = ""
    if self.no:
      prefix += " <"
    else:
      prefix += " >"
    if self.inclusiv.isChecked():
      prefix += "="

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

class FileIsDeleted(Ui_IsDeleted, QWidget):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.field = "\"deleted\""

  def text(self):
    if self.deleted.isChecked():
      return " == True"
    return " == False"

class IsFile(Ui_FileOrFolder, QWidget):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.field = "\"file\""

  def text(self):
    if self.isFile.isChecked():
      return " == True"
    return " == False"

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
                       typeId.Node: SearchDict,
                       typeId.Path: SearchDict,
                       typeId.VTime: SearchD,
                       typeId.Bool: FileIsDeleted,
                       typeId.List: MimeType,

                       # NEED TO BE CHANGED
                       typeId.Char + 100: SearchStr,
                       typeId.Int16 + 100: SearchS,
                       typeId.UInt16 + 100: SearchS,
                       typeId.Int32 + 100: SearchS,
                       typeId.UInt32 + 100: SearchS,
                       typeId.Int64  + 100: SearchS,
                       typeId.UInt64 + 100: SearchS,
                       typeId.String + 100: SearchStr,
                       typeId.CArray + 100: SearchStr,
                       typeId.Node + 100: SearchDict,
                       typeId.Path + 100: SearchDict,
                       typeId.VTime + 100: SearchD,
                       typeId.Bool + 100: IsFile}

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

class BuildSearchClause(QDialog, Ui_BuildSearchClause):
  def __init__(self, parent = None):
      super(QDialog, self).__init__()
      self.setupUi(self)
      self.translation()
      self.optionList.addItem(self.textTr, QVariant(typeId.String))
      self.optionList.addItem(self.notNameTr, QVariant(typeId.String + 100))
      self.optionList.addItem(self.NameTr, QVariant(typeId.String))
      self.optionList.addItem(self.notContains, QVariant(typeId.String + 100))
      self.optionList.addItem(self.sizeMinTr, QVariant(typeId.UInt64))
      self.optionList.addItem(self.sizeMaxTr, QVariant(typeId.UInt64 + 100))
      self.optionList.addItem(self.dateMaxTr, QVariant(typeId.VTime + 100))
      self.optionList.addItem(self.dateMinTr, QVariant(typeId.VTime))
      self.optionList.addItem(self.fromDictTr, QVariant(typeId.Path))
      self.optionList.addItem(self.dataDeletedTr , QVariant(typeId.Bool))
      self.optionList.addItem(self.dataIsFileTr, QVariant(typeId.Bool + 100))
      self.optionList.addItem(self.mimeTypeTr, QVariant(typeId.List))

      if QtCore.PYQT_VERSION_STR >= "4.5.0":
        self.addOption.clicked.connect(self.addSearchOptions)
      else:
        QtCore.QObject.connect(self.addOption, SIGNAL("clicked(bool)"), self.addSearchOptions)
      self.addedOpt = []

  def translation(self):
      self.textTr = self.tr("Contains")
      self.notNameTr = self.tr("Name does not contain")
      self.NameTr = self.tr("Name contain")
      self.fromDictTr = self.tr("From dictionnary")
      self.notContains = self.tr("Does not contain")
      self.sizeMinTr = self.tr("Size at least")
      self.sizeMaxTr = self.tr("Size at most")
      self.dateMaxTr = self.tr("Date less than")
      self.dateMinTr = self.tr("Date most than")
      self.dataDeletedTr = self.tr("Deleted")
      self.dataIsFileTr = self.tr("Type")
      self.mimeTypeTr = self.tr("Mime-type")

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
    opt = self.optionList.itemData(self.optionList.currentIndex()).toInt()[0]
    widget = OptWidget(self, opt)
    if (opt != (100 + typeId.Bool)) and (opt >= (100 + typeId.String)):
      widget.edit.setNo(True)
    if text == self.notNameTr: 
      widget.edit.field = "\"name\" "
    elif text == self.NameTr:
      widget.edit.field = "\"name\" "

    self.optionList.removeItem(self.optionList.currentIndex())
    widget.label.setText(text)

    widget.id = len(self.addedOpt)
    self.advancedOptions.addWidget(widget)
    self.addedOpt.append(widget)
    if not self.optionList.count():
      self.optionList.setEnabled(False)
      self.addOption.setEnabled(False)
