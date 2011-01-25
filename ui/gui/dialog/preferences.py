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

from PyQt4.QtGui import QDialog
from PyQt4.QtCore import SIGNAL, QEvent

from ui.gui.dialog.ui_preferences import Ui_PreferencesDialog
from ui.gui.configuration.conf import Conf
from ui.gui.configuration.translator import Translator

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

      # Populate languages comboBox with available languages, also set to current language
      self.langPopulate()

      # Signals handling
      self.connect(self.noHistoryCheckBox, SIGNAL("stateChanged(int)"), self.historyStateChanged)
      self.connect(self.langComboBox, SIGNAL("currentIndexChanged (const QString&)"), self.langChanged)
      
      if parent:
          self.app = parent.app
      else:
          self.app = None
      
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


# Signals related
    def historyStateChanged(self, state):
      # Checked state = 2, else state = 0.
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


