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

from PyQt4.QtCore import Qt, SIGNAL

from PyQt4.QtGui import QWidget, QLabel, QPushButton, QDialog, QTableWidget, QTableWidgetItem, QAbstractItemView, QIcon, QTreeWidgetItem, QCheckBox

from ui.gui.widget.mime_types import IndexMimeTypes

import os
import sys
import struct

class RootCheckBox(QCheckBox):
    def __init__(self):
        QCheckBox.__init__(self)
        self.children = []
        self.connect(self, SIGNAL("clicked()"), self.updateChildren)


    def addChild(self, child):
        self.children.append(child)


    def updateChildren(self):
        state = self.checkState()
        for child in self.children:
            if child.isEnabled():
                child.setCheckState(state)


    def update(self, val):
        checked = 0
        for child in self.children:
            if child.checkState() == Qt.Checked:
                checked += 1
        if checked == 0:
            self.setCheckState(Qt.Unchecked)
        elif self.checkState() == Qt.Unchecked:
            self.setCheckState(Qt.Checked)
            

class MimeTypesTree():
    def __init__(self, tree):
        self.mm = MimeTree()
        self.tree = tree
        self.typeItems = []
        self.populate()


    def populate(self):
        self.tree.connect(self.tree, SIGNAL("itemClicked(QTreeWidgetItem *, int)"), self.clicked)
        self.tree.connect(self.tree, SIGNAL("itemPressed(QTreeWidgetItem *, int)"), self.clicked)
        for mimetype, mimecontent in self.mm.mimetypes.iteritems():
            mimetypeItem = QTreeWidgetItem(self.tree, [mimetype])
            mimetypeItem.setFlags(Qt.ItemIsUserCheckable|Qt.ItemIsEnabled|Qt.ItemIsSelectable)
            mimetypeItem.setCheckState(0, Qt.Unchecked)
            rCheckBox = RootCheckBox()
            rCheckBox.setEnabled(False)
            self.tree.setItemWidget(mimetypeItem, 1, rCheckBox)
            self.typeItems.append(mimetypeItem)
            for value in mimecontent:
                filetypeItem = QTreeWidgetItem(mimetypeItem, [value])
                filetypeItem.setFlags(Qt.ItemIsUserCheckable|Qt.ItemIsEnabled|Qt.ItemIsSelectable)
                filetypeItem.setCheckState(0, Qt.Unchecked)
                checkBox = QCheckBox()
                checkBox.setEnabled(False)
                rCheckBox.addChild(checkBox)
                rCheckBox.connect(checkBox, SIGNAL("stateChanged(int)"), rCheckBox.update)
                self.tree.setItemWidget(filetypeItem, 1, checkBox)
        self.tree.resizeColumnToContents(0)


    def setCheckStateOfChildren(self, item, column, checked):
        children = item.childCount()
        for i in range(0, children):
            if checked == Qt.Checked:
                self.tree.itemWidget(item.child(i), 1).setEnabled(True)
            else:
                self.tree.itemWidget(item.child(i), 1).setCheckState(False)
                self.tree.itemWidget(item.child(i), 1).setEnabled(False)
            item.child(i).setCheckState(0, checked)


    def isAllChildren(self, item, column):
        children = item.childCount()
        checked = 0
        for i in range(0, children):
            if item.child(i).checkState(column) == Qt.Checked:
                checked += 1
        if checked == 0:
            self.tree.itemWidget(item, 1).setEnabled(False)
            item.setCheckState(0, Qt.Unchecked)
        elif item.checkState(column) == Qt.Unchecked:
            self.tree.itemWidget(item, 1).setEnabled(True)
            item.setCheckState(0, Qt.Checked)


    def clicked(self, item, column):
        if column == 0:
            if item.childCount() != 0:
                if item.checkState(0) == Qt.Checked:
                    self.tree.itemWidget(item, 1).setEnabled(True)
                    self.setCheckStateOfChildren(item, column, Qt.Checked)
                else:
                    self.tree.itemWidget(item, 1).setEnabled(False)
                    self.setCheckStateOfChildren(item, column, Qt.Unchecked)
            else:
                parent = item.parent()
                if parent != None and parent.childCount() != 0:
                    self.isAllChildren(parent, column)
                if item.checkState(0) == Qt.Checked:
                    self.tree.itemWidget(item, 1).setEnabled(True)
                else:
                    self.tree.itemWidget(item, 1).setEnabled(False)
                    self.tree.itemWidget(item, 1).setCheckState(False)
            

    def createGroupBox(self, items):
        gb = QGroupBox(items["type"])
        gb.setCheckable(True)
        gb.setChecked(False)
        vbox = QVBoxLayout()
        for item in items["value"]:
            button = QCheckBox(item)
            vbox.addWidget(button)
        vbox.addStretch(1)
        gb.setLayout(vbox)
        return gb


    def selectedItems(self):
        selected = []
        for typeItem in self.typeItems:
            i = 0
            if typeItem.checkState(0) == Qt.Checked:
                mimetype = str(typeItem.text(0))
                children = typeItem.childCount()
                tmplist = []
                ccount = 0
                for i in range(0, children):
                    child = typeItem.child(i)
                    if child.checkState(0) == Qt.Checked:
                        ccount += 1
                        if not child.isDisabled():
                            text = mimetype + "/" + str(child.text(0))
                            tmplist.append(text)
                if ccount == children:
                    selected.append(mimetype)
                else:
                    selected.extend(tmplist)
        return selected


class MimeTree():
    def __init__(self):
        self.mimetypes = {}
        if os.name == "nt":
            self.mgc = sys.path[0] + "./api/magic/magic.mgc"
        else:
            self.mgc = "/usr/share/misc/magic.mgc"
        try:
            self.mgcfile = open(self.mgc, 'rb')
        except:
            self.__err("can't open magic file")
        buff = self.mgcfile.read()
        lbuff = len(buff)
        if lbuff < 8:
            self.__err("magic file is too short")
        self.mgcsize = lbuff
        magicno, = struct.unpack("<I", buff[0:4])
        smagicno, = struct.unpack(">I", buff[0:4])
        bswap = False
        if magicno != 0xF11E041C:
            if smagicno != 0xF11E041C:
                self.__err("bad magic file")
            else:
                bswap = True
        if bswap:
            version, = struct.unpack(">I", buff[4:8])
        else:
            version, = struct.unpack("<I", buff[4:8])
        if version == 7:
            self.__maxoff = 64
        elif version == 8:
            self.__maxoff = 96
        else:
            self.__err("bad magic file version")
        self.nmagic = (self.mgcsize / (self.__maxoff + 136)) - 1
        self.populate(buff)


    def __err(self, msg):
        if self.mgcfile != None:
            self.mgcfile.close()
            del self.mgcfile
        raise RuntimeError(msg)


    def populate(self, buff):
        bpos = self.__maxoff + 136
        for i in xrange(0, self.nmagic):
            bpos += self.__maxoff
            desc, = struct.unpack("64s", buff[bpos:bpos+64])
            mime, = struct.unpack("64s", buff[bpos+64:bpos+128])
            if len(mime) and mime[0] != '\0':
                smime = mime.split("/", 1)
                if len(smime) == 2:
                    key = smime[0]
                    val = smime[1]
                    if not self.mimetypes.has_key(key):
                        self.mimetypes[key] = []
                    if val not in self.mimetypes[key]:
                        self.mimetypes[key].append(val)
            bpos += 136
