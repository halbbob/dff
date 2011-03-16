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

from PyQt4.QtGui import QDialog, QFileDialog, QMessageBox
from PyQt4.QtCore import SIGNAL, QEvent, QString

from ui.gui.resources.ui_preferences import Ui_PreferencesDialog
from ui.conf import Conf
from ui.gui.translator import Translator

import sys
from os import listdir, access, makedirs, R_OK, W_OK
from os.path import normpath, dirname

class Preferences(QDialog, Ui_PreferencesDialog):
    def __init__(self, parent = None):
      """ Drives preferences Dialog

      TODO
       - Valide index settings are properly handle by indexer
      """
      
      super(QDialog, self).__init__()
      
      # Set up the user interface from Qt Designer
      self.setupUi(self)
      self.translation()

      # Framework singleton classes
      self.conf = Conf()
      self.translator = Translator()

      # Temporary config, to be validated once submited
      self.tNoFootPrint = self.conf.noFootPrint
      self.tNoHistoryFile = self.conf.noHistoryFile
      self.tWorkPath = self.conf.workingDir
      self.tHistoryFileFullPath = self.conf.historyFileFullPath

      if self.conf.indexEnabled:
          self.tRootIndex = self.conf.root_index
          self.tIndexName = self.conf.index_name
          self.tIndexPath = self.conf.index_path
      else:
          idx = self.tabWidget.indexOf(self.indexTab)
          self.tabWidget.removeTab(idx)
      # Activate preferences from conf values
      self.noFootPrintCheckBox.setChecked(self.conf.noFootPrint)
      self.noHistoryCheckBox.setChecked(self.conf.noHistoryFile)
      self.footprintOrNo()

      self.workingDirPath.setText(self.conf.workingDir)
      self.historyLineEdit.setText(self.conf.historyFileFullPath)
      self.docAndHelpFullPath.setText(self.conf.docPath)
      
      # Populate languages comboBox with available languages, also set to current language
      self.langPopulate()

      # Signals handling
      self.connect(self.noFootPrintCheckBox, SIGNAL("stateChanged(int)"), self.noFootPrintChanged)
      self.connect(self.workingDirBrowse, SIGNAL("clicked()"), self.workDir)
      self.connect(self.historyToolButton, SIGNAL("clicked()"), self.historyDir)
      self.connect(self.noHistoryCheckBox, SIGNAL("stateChanged(int)"), self.historyStateChanged)
      self.connect(self.langComboBox, SIGNAL("currentIndexChanged (const QString&)"), self.langChanged)

      # indexation configuration
      if self.conf.indexEnabled:
          self.init_index_pref()

      # Help configuration
      self.connect(self.docAndHelpBrowse, SIGNAL("clicked()"), self.helpDir)

      # Show or hide label helpers
      self.globalValid()
      self.helpValid()
      
      if parent:
          self.app = parent.app
      else:
          self.app = None

      # Catch submit to create directories if needed
      self.connect(self.buttonBox, SIGNAL("accepted()"), self.validate)
      self.connect(self.buttonBox, SIGNAL("rejected()"), self.clear)
      
    def validate(self):
        if not self.tNoFootPrint and not access(self.tWorkPath, R_OK):
            if QMessageBox.question(self, self.createDirTitle, self.createDirTitle + ':<br>' + self.tWorkPath + '?', QMessageBox.Yes, QMessageBox.No) == QMessageBox.No:
                return
            else:
                try:
                    makedirs(self.tWorkPath, 0700)
                except OSError, e:
                    QMessageBox.warning(self, self.createDirFail, self.createDirFail + ':<br>' + self.tWorkPath + '<br>' + e.strerror)
                    return
        self.conf.workingDir = self.tWorkPath
        if self.tNoFootPrint != self.conf.noFootPrint:
            self.conf.noFootPrint = self.tNoFootPrint
        if not self.tNoFootPrint and self.conf.indexEnabled and not access(self.tIndexPath, R_OK):
            if QMessageBox.question(self, self.createDirTitle, self.createDirTitle + ':<br>' + self.tIndexPath + '?', QMessageBox.Yes, QMessageBox.No) == QMessageBox.No:
                return
            else:
                try:
                    makedirs(self.tIndexPath, 0700)
                except OSError, e:
                    QMessageBox.warning(self, self.createDirFail, self.createDirFail + ':<br>' + self.tIndexPath + '<br>' + e.strerror)
                    return
        if self.conf.indexEnabled:
            self.conf.root_index = self.tRootIndex
            self.conf.index_name = self.tIndexName
            self.conf.index_path = self.tIndexPath
        self.conf.noHistoryFile = self.tNoHistoryFile
        if (not self.tNoHistoryFile and not self.tNoFootPrint) and self.tHistoryFileFullPath != self.conf.historyFileFullPath and access(dirname(self.tHistoryFileFullPath), W_OK):
            self.conf.historyFileFullPath = self.tHistoryFileFullPath
        elif (not self.tNoHistoryFile and not self.tNoFootPrint) and not access(dirname(self.tHistoryFileFullPath), W_OK):
            QMessageBox.warning(self, self.histWriteFail, self.histWriteFail + ':<br>' + self.tHistoryFileFullPath)
            return
        self.conf.save()
        self.accept()
        return

    def clear(self):
        self.reject()
        return

    def footprintOrNo(self):
        """
        Enable or disable inputs which made changes on the system
        """
        # Working dir related
        self.workingDirPath.setEnabled(not self.tNoFootPrint)
        self.workingDirBrowse.setEnabled(not self.tNoFootPrint)
        # History related
        self.historyLineEdit.setEnabled(not self.tNoFootPrint and not self.tNoHistoryFile)
        self.historyToolButton.setEnabled(not self.tNoFootPrint and not self.tNoHistoryFile)
        self.noHistoryCheckBox.setEnabled(not self.tNoFootPrint)
        # Indexes related
        if self.conf.indexEnabled:
            self.indexTab.setEnabled(not self.tNoFootPrint)

        # Refresh label helpers
        self.globalValid()
        if self.conf.indexEnabled:
            self.indexValid()

    def workDir(self):
        """
        Handle a new working directory
        """
        f_dialog = self.fileDialog(self.conf.workingDir)
        if f_dialog.exec_():
            self.workingDirPath.setText(f_dialog.selectedFiles()[0])
            self.tWorkPath = f_dialog.selectedFiles()[0]
            if not access(self.conf.historyFileFullPath, R_OK):
                # History file does not exists and working dir has changed, update history path
                self.conf.historyFileFullPath = normpath(str(self.tWorkPath + '/history'))
                self.historyLineEdit.setText(self.conf.historyFileFullPath)
            if self.conf.indexEnabled and not access(self.tRootIndex, R_OK):
                # Index directory does not exists and working dir has changed, update index path
                self.tRootIndex = normpath(str(self.tWorkPath) + '/indexes/')
                self.tIndexPath = normpath(self.tRootIndex + '/' + self.tIndexName)
                self.root_index_line.setText(self.tRootIndex)
            self.globalValid()
            if self.conf.indexEnabled:
                self.indexValid()

    def historyDir(self):
        """
        Handle a new history file
        """
        f_dialog = self.fileDialog(self.tHistoryFileFullPath, QFileDialog.ExistingFile)
        if f_dialog.exec_():
            self.historyLineEdit.setText(f_dialog.selectedFiles()[0])
            self.tHistoryFileFullPath = f_dialog.selectedFiles()[0]
        
    def helpDir(self):
        """
        Handle a new help.qhc file.
        Be carreful ; an help.qch file must also exists at the same directory level.
        """
        f_dialog = self.fileDialog(self.conf.docPath, QFileDialog.ExistingFile)
        if f_dialog.exec_():
            self.docAndHelpFullPath.setText(f_dialog.selectedFiles()[0])
            self.conf.docPath = f_dialog.selectedFiles()[0]
            self.helpValid()

    def globalValid(self):
        """
        Set labels 'path exists' or no in global tab.
        """
        # No footprint. hide all help labels in this tab
        if self.tNoFootPrint:
            self.workDirWillCreate.setVisible(False)
            self.workDirOK.setVisible(False)
            return
            
        # Does working dir exists ?
        if access(self.tWorkPath, R_OK):
            self.workDirWillCreate.setVisible(False)
            self.workDirOK.setVisible(True)
        else:
            self.workDirWillCreate.setVisible(True)
            self.workDirOK.setVisible(False)
        
    def helpValid(self):
        """
        Set label 'path exists' or no in help tab.
        """
        if access(self.conf.docPath, R_OK):
            self.helpNOK.setVisible(False)
            self.helpOK.setVisible(True)
        else:
            self.helpNOK.setVisible(True)
            self.helpOK.setVisible(False)

    def indexValid(self):
        """
        Set label 'path exists' or no in help tab.
        """
        if access(self.tIndexPath, R_OK):
            self.indexDirWillCreate.setVisible(False)
            self.indexDirOK.setVisible(True)
        else:
            self.indexDirWillCreate.setVisible(True)
            self.indexDirOK.setVisible(False)

    def init_index_pref(self):
        """
        Initialize the configuration of the indexation.
        """
        self.root_index_line.setText(self.conf.root_index)
        self.index_name_line.setText(self.conf.index_name)

        # Signal handling for browse buttons.
        self.connect(self.root_index_button, SIGNAL("clicked()"), self.conf_root_index_dir)
        self.connect(self.index_name_button, SIGNAL("clicked()"), self.conf_index_name_dir)

    def fileDialog(self, basePath, browseType = QFileDialog.DirectoryOnly):
        f_dialog = QFileDialog()
        f_dialog.setDirectory(basePath)
        if browseType == QFileDialog.DirectoryOnly:
            f_dialog.setFileMode(QFileDialog.DirectoryOnly)
            f_dialog.setOption(QFileDialog.ShowDirsOnly, True)
        else:
            f_dialog.setFileMode(QFileDialog.ExistingFile)
        return f_dialog
        
    def conf_root_index_dir(self):
        """
        This slot is used to set the root index directory.
        """
        f_dialog = self.fileDialog(self.root_index_line.text())
        if f_dialog.exec_():
            self.root_index_line.setText(f_dialog.selectedFiles()[0])
            self.tRootIndex = normpath(str(f_dialog.selectedFiles()[0]) + '/indexes/')
#            self.conf.root_index = self.root_index_line.text()

    def conf_index_name_dir(self):
        """
        This slot is used to set the index directory.
        """
        f_dialog = self.fileDialog(self.index_name_line.text())
        if f_dialog.exec_():
            name = str(f_dialog.selectedFiles()[0])
            # FIXME windows ?
            pos = name.rfind("/")
            if pos != -1:
                name = name[pos + 1:]
            self.index_name_line.setText(name)
            self.tIndexName = normpath(name)
            self.tIndexPath = normpath(self.tRootIndex + '/' + name)
            
#            self.conf.index_name = name
#            self.conf.index_path = self.conf.root_index + "/" + name

    def langPopulate(self):
        translationPath = normpath(sys.modules['ui.gui'].__path__[0] + '/i18n/')
        i = 0
        selected = 0
        for oneFile in listdir(translationPath):
            if oneFile.startswith('Dff_') and oneFile.endswith('.qm'):
                self.langComboBox.addItem(oneFile[len('Dff_'):-len('.qm')])
                if self.conf.language == oneFile[len('Dff_'):-len('.qm')]:
                    selected = i
                i += 1
        self.langComboBox.setCurrentIndex(selected)

    def noFootPrintChanged(self, state):
        self.tNoFootPrint = (state == 2)
        self.footprintOrNo()
        
    def historyStateChanged(self, state):
        self.tNoHistoryFile = (state == 2)
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
            self.translation()
            self.retranslateUi(self)
        else:
            QDialog.changeEvent(self, event)

    def translation(self):
        self.createDirTitle = self.tr('Create directory')
        self.createDirFail =self.tr('Directory creation failure')
        self.histWriteFail = self.tr('History file is not writable')
        

