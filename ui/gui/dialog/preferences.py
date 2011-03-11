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
#  Christophe Malinge <cma@digital-forensic.org>
#

from PyQt4.QtGui import QDialog, QFileDialog
from PyQt4.QtCore import SIGNAL, QEvent, QString, QDir

from ui.gui.resources.ui_preferences import Ui_PreferencesDialog
from ui.conf import Conf
from ui.gui.translator import Translator

import os, sys

class Preferences(QDialog, Ui_PreferencesDialog):
    def __init__(self, parent = None):
      """ Drives preferences Dialog

      TODO
       - Set states and variables from configuration singleton values.
       - Add Help filepath
       - Develop history and noffotprint modes
      """
      
      super(QDialog, self).__init__()
      
      # Set up the user interface from Qt Designer
      self.setupUi(self)

      # Framework singleton classes
      self.conf = Conf()
      self.translator = Translator()

      # Activate preferences from conf values
      self.noFootPrintCheckBox.setChecked(self.conf.noFootPrint)
      self.footprintOrNo()

      self.workingDirPath.setText(self.conf.workingDir)
      self.historyLineEdit.setText(self.conf.historyFileFullPath)
      self.docAndHelpFullPath.setText(self.conf.docPath)
      
      # Populate languages comboBox with available languages, also set to current language
      self.langPopulate()

      # Signals handling
      self.connect(self.noFootPrintCheckBox, SIGNAL("stateChanged(int)"), self.noFootPrintChanged)
      self.connect(self.noHistoryCheckBox, SIGNAL("stateChanged(int)"), self.historyStateChanged)
      self.connect(self.langComboBox, SIGNAL("currentIndexChanged (const QString&)"), self.langChanged)

      # indexation configuration
      self.init_index_pref()
      
      if parent:
          self.app = parent.app
      else:
          self.app = None

    def footprintOrNo(self):
        """
        Enable or disable inputs which made changes on the system
        """
        # Working dir related
        self.workingDirPath.setEnabled(not self.conf.noFootPrint)
        self.workingDirBrowse.setEnabled(not self.conf.noFootPrint)
        # History related
        self.historyLineEdit.setEnabled(not self.conf.noFootPrint)
        self.historyToolButton.setEnabled(not self.conf.noFootPrint)
        self.noHistoryCheckBox.setEnabled(not self.conf.noFootPrint)
        # Indexes related
        self.root_index_line.setEnabled(not self.conf.noFootPrint)
        self.root_index_button.setEnabled(not self.conf.noFootPrint)
        self.index_name_line.setEnabled(not self.conf.noFootPrint)
        self.index_name_button.setEnabled(not self.conf.noFootPrint)

    def init_index_pref(self):
        """
        Initialize the configuration of the indexation.
        """
        self.root_index_line.setText(self.conf.root_index)
        self.index_name_line.setText(self.conf.index_name)

        # Signal ahndling for browse buttons.
        self.connect(self.root_index_button, SIGNAL("clicked()"), self.conf_root_index_dir)
        self.connect(self.index_name_button, SIGNAL("clicked()"), self.conf_index_name_dir)

    def conf_root_index_dir(self):
        """
        This slot is used to set the root index directory.
        """
        f_dialog = QFileDialog()
        f_dialog.setDirectory(self.conf.root_index)
        f_dialog.setFileMode(QFileDialog.DirectoryOnly)
        f_dialog.setOption(QFileDialog.ShowDirsOnly, True)
        res = f_dialog.exec_()

        self.root_index_line.setText(f_dialog.selectedFiles()[0])
        self.conf.root_index = self.root_index_line.text()

    def conf_index_name_dir(self):
        """
        This slot is used to set the index directory.
        """
        f_dialog = QFileDialog()
        f_dialog.setDirectory(self.conf.index_path)
        f_dialog.setFileMode(QFileDialog.DirectoryOnly)
        f_dialog.setOption(QFileDialog.ShowDirsOnly, True)
        res = f_dialog.exec_()
        name = str(f_dialog.selectedFiles()[0])
        pos = name.rfind("/")
        if pos != -1:
            name = name[pos + 1:]
        self.index_name_line.setText(name)
        self.conf.index_name = name
        self.conf.index_path = self.conf.root_index + "/" + name

    def langPopulate(self):
        translationPath = sys.modules['ui.gui'].__path__[0] + '/i18n/'
        i = 0
        selected = 0
        for oneFile in os.listdir(translationPath):
            if oneFile.startswith('Dff_') and oneFile.endswith('.qm'):
                self.langComboBox.addItem(oneFile[len('Dff_'):-len('.qm')])
                if self.conf.language == oneFile[len('Dff_'):-len('.qm')]:
                    selected = i
                i += 1
        self.langComboBox.setCurrentIndex(selected)

    def noFootPrintChanged(self, state):
        self.conf.noFootPrint = (state == 2)
        self.footprintOrNo()
        
    def historyStateChanged(self, state):
        self.historyLabel.setEnabled((state == 0))
        self.historyLineEdit.setEnabled((state == 0))
        self.historyToolButton.setEnabled((state == 0))

    def langChanged(self, text):
        """ Change interface language

        Sets language in configuration singleton.
        Removes previous translator.
        Updates translator with new language.
        Installs translator using new language.
        """
        self.conf.setLanguage(text)
        self.app.removeTranslator(self.translator.getGeneric())
        self.app.removeTranslator(self.translator.getDFF())
        self.translator.loadLanguage()
        self.app.installTranslator(self.translator.getGeneric())
        self.app.installTranslator(self.translator.getDFF())

    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
        else:
            QDialog.changeEvent(self, event)


