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

import os

from PyQt4.QtGui import QFileDialog, QMessageBox, QInputDialog, QDialog, QDialogButtonBox, QComboBox, QPushButton, QFormLayout, QHBoxLayout, QPixmap, QLabel, QApplication
from PyQt4.QtCore import QObject, QString, SIGNAL, SLOT, Qt, QEvent

from api.taskmanager import *
from api.taskmanager.taskmanager import * 
from api.loader import *
from api.vfs import vfs
from api.devices.devices import Devices
from api.gui.widget.devicesdialog import DevicesDialog

from ui.gui.dialog.preferences import Preferences
from ui.gui.resources.ui_about import Ui_About
from ui.gui.resources.ui_evidencedialog import Ui_evidenceDialog

class Dialog(QObject):
  def __init__(self, parent):
     QObject.__init__(self)
     self.parent = parent 
     self.env = env.env()
     self.vfs = vfs.vfs()
     self.taskmanager = TaskManager()
     self.loader = loader.loader()

  def preferences(self):
    """Open a preferences dialog"""
    
    pref = Preferences(self.parent)
    pref.exec_()

  def addDevices(self):
       """Open a device list dialog"""
       dev = DevicesDialog(self.parent)
       if dev.exec_():
	 if dev.selectedDevice:
           arg = self.env.libenv.argument("gui_input")
           arg.thisown = 0
	   arg.add_path("path", str(dev.selectedDevice.blockDevice())) 
           arg.add_node("parent", self.vfs.getnode("/"))
           arg.add_uint64("size", long(dev.selectedDevice.size())) 
	   exec_type = ["thread", "gui"]
           if os.name == "nt":
             arg.add_string("name", str(dev.selectedDevice.model()))	   
             self.taskmanager.add("windevices", arg, exec_type)	
           else:	   
             self.taskmanager.add("local", arg, exec_type)

  def addFiles(self):
        """ Open a Dialog for select a file and add in VFS """
        edialog = evidenceDialog(self.parent)
        ir = edialog.exec_()
        if ir > 0:
          dtype = edialog.comboformat.itemData(edialog.comboformat.currentIndex()).toString()
          # RAW files # EWF files # Local directory
          if dtype == 'dir':
            sFiles = QFileDialog.getExistingDirectory(self.parent, edialog.actionAdd_evidence_directory.text(), os.path.expanduser('~'))
          elif dtype == 'ewf' or dtype == 'raw':
            sFiles = QFileDialog.getOpenFileNames(self.parent, edialog.actionAdd_evidence_files.text(),  os.path.expanduser('~'))

          if len(sFiles) > 0:
            if dtype != 'dir':
              for name in sFiles:
                arg = self.env.libenv.argument("gui_input")
                arg.thisown = 0
                exec_type = ["thread", "gui"]
                if dtype == 'ewf':
                  arg.add_path("file", str(name))
                  self.taskmanager.add("ewf", arg, exec_type)
                else:
                  arg.add_path("path", str(name))
                  arg.add_node("parent", self.vfs.getnode("/"))
                  self.taskmanager.add("local", arg, exec_type)
            else:
              arg = self.env.libenv.argument("gui_input")
              arg.thisown = 0
              exec_type = ["thread", "gui"]
              arg.add_path("path", str(sFiles))
              arg.add_node("parent", self.vfs.getnode("/"))
              self.taskmanager.add("local", arg, exec_type)
 
  def loadDriver(self):
        sFileName = QFileDialog.getOpenFileName(self.parent, self.parent.actionLoadModule.toolTip(), os.path.expanduser('~'),  "Modules(*.py)")
        if (sFileName) :
            self.loader.do_load(str(sFileName))

  def about(self):
        """ Open a About Dialog """
        about = About()
        about.exec_()


class About(QDialog, Ui_About):
  def __init__(self):
    super(QDialog, self).__init__()
    self.setupUi(self)
    self.label.setText(self.label.text().arg(QApplication.instance().applicationVersion()))

  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.retranslateUi(self)
      self.label.setText(self.label.text().arg(QApplication.instance().applicationVersion()))
    else:
      QDialog.changeEvent(self, event)


class evidenceDialog(QDialog, Ui_evidenceDialog):
  def __init__(self, parent):
    super(QDialog, self).__init__()
    self.setupUi(self)
    self.loader = loader.loader()
    self.createShape()


  def createShape(self):
    """ Removes EWF if not in modules

    Set itemData for easy access without taking care of text (can be
    translated).
    TODO Futur : Get all DFF connectors
    """
    
    # 
    self.comboformat.setItemData(0, QString('raw'))
    self.comboformat.setItemData(1, QString('ewf'))
    self.comboformat.setItemData(2, QString('dir'))
    
    if "ewf" not in self.loader.modules:
      self.comboformat.removeItem(1)

  def changeEvent(self, event):
    """ Search for a language change event
    
    This event have to call retranslateUi to change interface language on
    the fly.
    """
    if event.type() == QEvent.LanguageChange:
      self.retranslateUi(self)
      self.label.setText(self.label.text().arg(QApplication.instance().applicationVersion()))
    else:
      QDialog.changeEvent(self, event)
