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

from PyQt4 import QtCore, QtGui

from PyQt4.QtCore import Qt

from PyQt4.QtGui import QWidget, QLabel, QPushButton, QDialog, QTableWidget, QTableWidgetItem, QAbstractItemView, QIcon, QTreeWidgetItem

from ui.gui.widget.mime_types import IndexMimeTypes

import sys

class MimeTypesTree():
    def __init__(self, mime_type_list):
        self.icons = {"application/images" : ":/image.png",
                      "application/videos" : ":/video.png",
                      "application/animation" : ":/presentation.png",
                      "application/document": ":/document.png",
                      "application/mail" : ":/mail_generic",
                      "application/audio" : ":/sound.png",
                      "application/pgp" : ":/password.png",
                      "application/package" : ":/file.png",
                      "application/registry" : ":/spreadsheet.png",
                      "application/archiver": ":/zip",
                      "application/vm" : ":/virtualize.png",
                      }

        self.types = IndexMimeTypes()
        mime_type_list.setColumnCount(1)
        self.root = mime_type_list.invisibleRootItem()
        self.build_tree()

    def build_tree(self):
        for i in self.types.types:
            l_type = self.types.types[i](self.types)
            sub_root = self.buildSubRootItem(i)
            type_list = []
            for ty in l_type:
                new_item = QTreeWidgetItem([ty])
                new_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                new_item.setCheckState(0, Qt.Unchecked)
                sub_root.insertChild(0, new_item)
            self.root.insertChild(0, sub_root)

    def buildSubRootItem(self, name):
        new_item = QTreeWidgetItem([name])
        new_item.setIcon(0, QIcon(self.icons[name]))
        return new_item
