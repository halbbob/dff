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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from ui.gui.utils.utils import Utils

class WIntroPage(QWizardPage):
    def __init__(self, parent):
        QWizardPage.__init__(self, parent)
        self.setInformations()
        self.createShape()

    def setInformations(self):
        self.setTitle(self.tr("Script Informations"))
        self.setSubTitle(self.tr("Fill all script information such as name, type and saving location"))
        firstpix = QPixmap(":script-new.png")
        pix = firstpix.scaledToWidth(64)
        self.setPixmap(QWizard.LogoPixmap, pix)

    def createShape(self):
        self.layout = QFormLayout()
        lname = QLabel(self.tr("Name"))
        self.name = QLineEdit()

        ltype = QLabel(self.tr("Type"))
        self.groupButton = QVBoxLayout()
        self.type_script = QRadioButton(self.tr("Script"))
        self.type_script.setChecked(True)
        self.type_graphical = QRadioButton(self.tr("Graphical"))
        self.type_driver = QRadioButton(self.tr("Driver"))
        self.groupButton.addWidget(self.type_script)
        self.groupButton.addWidget(self.type_graphical)
        self.groupButton.addWidget(self.type_driver)


        lcat = QLabel(self.tr("Category"))
        self.category = QComboBox()
        self.category.setEditable(True)
        self.tags = []
        setags = Utils.getSetTags()
        for tag in setags:
            if not tag == "builtins":
                self.tags.append(tag)
                self.category.addItem(QString(tag))

        locationlayout = QHBoxLayout()
        lpath = QLabel(self.tr("Work location"))
        self.path = QLineEdit()
        self.path.setReadOnly(True)
        locationlayout.addWidget(self.path)
        self.brwButton = QPushButton(self.tr("Browse"))
        locationlayout.addWidget(self.brwButton)
        self.connect(self.brwButton, SIGNAL("clicked()"),  self.browseBack)

        self.layout.addRow(lname, self.name)
        self.layout.addRow(lcat, self.category)
        self.layout.addRow(lpath, locationlayout)
        self.layout.addRow(ltype, self.groupButton)
        
        ## Register Fields
        self.registerField("typeS", self.type_script)
        self.registerField("typeG", self.type_graphical)
        self.registerField("typeD", self.type_driver)
        self.registerField("name*", self.name)
        self.registerField("path*", self.path)
        self.setLayout(self.layout)

    def browseBack(self):
        dirName = QFileDialog.getExistingDirectory(self, self.tr("Location"))
        self.path.setText(dirName)

class WDescriptionPage(QWizardPage):
    def __init__(self, parent):
        QWizardPage.__init__(self, parent)
        self.setInformations()
        self.createShape()

    def setInformations(self):
        self.setTitle(self.tr("Script Description"))
        self.setSubTitle(self.tr("Describe here the goal of the module"))
        firstpix = QPixmap(":script-new.png")
        pix = firstpix.scaledToWidth(64)
        self.setPixmap(QWizard.LogoPixmap, pix)

    def createShape(self):
        self.layout = QFormLayout()
        ldesc = QLabel(self.tr("Module's description"))
        self.description = QTextEdit()

        self.layout.addRow(ldesc, self.description)

        self.registerField("description", self.description, "plainText")

        self.setLayout(self.layout)
        


class WAuthorPage(QWizardPage):
    def __init__(self, parent):
        QWizardPage.__init__(self, parent)
        self.setInformations()
        self.createShape()
        self.setFinalPage(True)

    def setInformations(self):
        self.setTitle(self.tr("Author Informations"))
        self.setSubTitle(self.tr("Fill all author's informations in order to complete header"))
        firstpix = QPixmap(":script-new.png")
        pix = firstpix.scaledToWidth(64)
        self.setPixmap(QWizard.LogoPixmap, pix)

    def createShape(self):
        self.layout = QFormLayout()

        lfname = QLabel(self.tr("Author's first name:"))
        self.auth_fname = QLineEdit()
        llname = QLabel(self.tr("Author's last name:"))
        self.auth_lname = QLineEdit()
        lmail = QLabel(self.tr("Author's electronic mail:"))
        self.auth_mail = QLineEdit()
        ## Register Fields
        self.registerField("authFName*", self.auth_fname)
        self.registerField("authLName*", self.auth_lname)
        self.registerField("authMail*", self.auth_mail)


        self.layout.addRow(lfname, self.auth_fname)
        self.layout.addRow(llname, self.auth_lname)
        self.layout.addRow(lmail, self.auth_mail)

        self.setLayout(self.layout)

    def browseBack(self):
        dirName = QFileDialog.getExistingDirectory(self, self.tr("Location"))
        self.path.setText(dirName)
