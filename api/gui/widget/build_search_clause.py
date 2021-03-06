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
from ui.gui.resources.ui_search_str import Ui_SearchStr
from ui.gui.resources.ui_search_dict import Ui_SearchDict
from ui.gui.resources.ui_is_file_or_folder import Ui_FileOrFolder
from ui.gui.resources.ui_is_deleted import Ui_IsDeleted
from ui.gui.resources.ui_search_mime_type import Ui_MimeType
from ui.gui.resources.ui_build_search_clause import Ui_BuildSearchClause
from ui.gui.resources.ui_edit_dict import Ui_DictListEdit
from ui.gui.resources.ui_search_attrs import Ui_SearchAttributes

from ui.gui.widget.SelectMimeTypes import MimeTypesTree

class MimeType(Ui_MimeType, QWidget):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.translation()
    self.text_t = ""
    self.field = "mime"
    self.selected_mime_types.hide()
    self.mime_types.setHeaderLabels([self.mimeTypeTr])
    self.mime = MimeTypesTree(self.mime_types)
    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.mime_types.clicked.connect(self.editMimeTypes)
    else:
      QtCore.QObject.connect(self.mime_types, SIGNAL("clicked(bool)"), self.editMimeTypes)
    
  def editMimeTypes(self, changed):
      self.selected_mime_types.clear()
      selectedItems = self.mime.selectedItems()
      for item in selectedItems:
        self.selected_mime_types.addItem(item)

  def text(self):
    text_t = " in ["
    for i in range(0, self.selected_mime_types.count()):
      if i != 0:
        text_t += ", "
      text_t += ("\"" +  self.selected_mime_types.itemText(i) + "\"")
    text_t += "]"
    return text_t

  def translation(self):
    self.mimeTypeTr = self.tr("Select one or several mime-types")

class SearchAttributes(Ui_SearchAttributes, QWidget):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.field = ""

    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.attrName.textChanged.connect(self.updateField)
    else:
      QtCore.QObject.connect(self.attrName, SIGNAL("textChanged(QString)"), self.updateField)

  def updateField(self, text):
    self.field = "\"" + text + "\""

  def text(self):
    if self.field.isEmpty() or self.attrValue.text().isEmpty():
      return ""
    return self.operator() + " " + self.attrValue.text()

  def operator(self):
    return self.attrOperator.currentText()

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
    self.field = "data"

    self.type.addItem("Fixed string", QVariant("f"))
    self.type.addItem("Wildcard", QVariant("w"))
    self.type.addItem("Fuzzy", QVariant("fz"))
    self.type.addItem("Reg exp", QVariant("re"))

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

    search += ("(\"" + str(self.name.text()))
    if not self.caseSensitive.isChecked():
      search += "\",i)"
    else:
      search += "\")"
    return str(search)

class SearchDict(QWidget, Ui_SearchDict):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.translation()
    self.word_list = []

    self.field = " data contains dict"

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
    Open a dialog box where the user can choose which file to load.
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
    text =  "(\"" + self.pathToDict.text() + "\")"
    return text

  def translation(self):
    self.errTr = "Cannot read the file."

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
    #if self.date_str.isChecked():
    return prefix + str(date_time.toString("yyyy-MM-ddThh:mm:ss"))
    #return prefix + "ts(" + str(date_time.toTime_t()) + ")"

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
    self.kiloTr = self.tr("Kilo byte(s)")
    self.megaTr = self.tr("Mega byte(s)")
    self.gigaTr = self.tr("Giga byte(s)")

class FileIsDeleted(Ui_IsDeleted, QWidget):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.field = "deleted"

  def text(self):
    if self.deleted.isChecked():
      return " == true"
    return " == false"

class IsFile(Ui_FileOrFolder, QWidget):
  def __init__(self, parent = None):
    super(QWidget, self).__init__()
    self.setupUi(self)
    self.field = "file"

  def text(self):
    if self.isFile.isChecked():
      return " == true"
    return " == false"

class OptWidget(QWidget):
  def __init__(self, parent, w_type = 0):
    super(QWidget, self).__init__()
    self.layout = QHBoxLayout(self)
    self.layout.setMargin(0)
    self.layout.setSpacing(0)
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
                       #typeId.Node: SearchDict,
                       #typeId.Path: SearchDict,
                       typeId.VTime: SearchD,
                       typeId.Bool: FileIsDeleted,
                       typeId.List: MimeType,
                       typeId.Argument: SearchAttributes,

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
                       #typeId.Node + 100: SearchDict,
                       #typeId.Path + 100: SearchDict,
                       typeId.VTime + 100: SearchD,
                       typeId.Bool + 100: IsFile}

    self.parent = parent
    self.id = -1
    self.label = QLabel()
    self.layout.addWidget(self.label)
    self.edit = self.value(w_type)
    self.layout.addWidget(self.edit)
    self.button = QPushButton(QIcon(":remove.png"), "", self)
    self.button.setFlat(True)
    self.button.setIconSize(QtCore.QSize(16, 16))
    self.button.setToolTip(self.delTr)
    self.layout.addWidget(self.button)
    if QtCore.PYQT_VERSION_STR >= "4.5.0":
      self.button.clicked.connect(self.removeOption)
    else:
      QtCore.QObject.connect(self.button, SIGNAL("clicked(bool)"), self.removeOption)
    
  def removeOption(self, changed):
    text = self.label.text()
    if self.type != typeId.Argument:
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
#      self.setWindowsTitle(
      self.optionList.addItem(self.textTr, QVariant(typeId.String))
      self.optionList.addItem(self.notNameTr, QVariant(typeId.String + 100))
      self.optionList.addItem(self.NameTr, QVariant(typeId.String))
      self.optionList.addItem(self.notContains, QVariant(typeId.String + 100))
      self.optionList.addItem(self.sizeMinTr, QVariant(typeId.UInt64))
      self.optionList.addItem(self.sizeMaxTr, QVariant(typeId.UInt64 + 100))
      self.optionList.addItem(self.dateMaxTr, QVariant(typeId.VTime + 100))
      self.optionList.addItem(self.dateMinTr, QVariant(typeId.VTime))
      #self.optionList.addItem(self.fromDictTr, QVariant(typeId.Path))
      self.optionList.addItem(self.dataDeletedTr , QVariant(typeId.Bool))
      self.optionList.addItem(self.dataIsFileTr, QVariant(typeId.Bool + 100))
      self.optionList.addItem(self.mimeTypeTr, QVariant(typeId.List))

      if QtCore.PYQT_VERSION_STR >= "4.5.0":
        self.addOption.clicked.connect(self.addSearchOptions)
        self.addXtdAttrs.clicked.connect(self.addAttrSearchOptions)
      else:
        QtCore.QObject.connect(self.addOption, SIGNAL("clicked(bool)"), self.addSearchOptions)
        QtCore.QObject.connect(self.addXtdAttrs, SIGNAL("clicked(bool)"), self.addAttrSearchOptions)
      self.addedOpt = []

  def translation(self):
      self.textTr = self.tr("Contains")
      self.notNameTr = self.tr("Name does not contain")
      self.NameTr = self.tr("Name contains")
      self.fromDictTr = self.tr("From dictionary")
      self.notContains = self.tr("Does not contain")
      self.sizeMinTr = self.tr("Size at least")
      self.sizeMaxTr = self.tr("Size at most")
      self.dateMaxTr = self.tr("Date less than")
      self.dateMinTr = self.tr("Date most than")
      self.dataDeletedTr = self.tr("Deleted")
      self.dataIsFileTr = self.tr("Type")
      self.mimeTypeTr = self.tr("Mime-type")
      self.attrTr = self.tr("Extended attributes")

  def addAttrSearchOptions(self, changed):
    widget = OptWidget(self, typeId.Argument)
    widget.label.setText(self.attrTr)
    widget.id = len(self.addedOpt)
    widget.edit.field = widget.edit.attrName.text()
    self.advancedOptions.addWidget(widget)
    self.addedOpt.append(widget)

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
      widget.edit.field = "name "
    elif text == self.NameTr:
      widget.edit.field = "name "

    self.optionList.removeItem(self.optionList.currentIndex())
    widget.label.setText(text)

    widget.id = len(self.addedOpt)
    self.advancedOptions.addWidget(widget)
    self.addedOpt.append(widget)
    if not self.optionList.count():
      self.optionList.setEnabled(False)
      self.addOption.setEnabled(False)
