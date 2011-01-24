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
#  Pablo Rogina <pablojr@gmail.com>
# 

from PyQt4.QtGui import QFileDialog, QMessageBox, QInputDialog, QTableWidget, QTableWidgetItem, QDialog, QHBoxLayout, QPushButton, QVBoxLayout, QSplitter
from PyQt4.QtCore import QString, Qt, SIGNAL, SLOT

from api.taskmanager import *
from api.taskmanager.taskmanager import *
from api.loader import *
from api.vfs import vfs
from api.devices.devices import Devices

from api.gui.widget.ui_devicesdialog import Ui_DevicesDialog

class DevicesDialog(QDialog, Ui_DevicesDialog):
    def __init__(self, parent = None):
        QDialog.__init__(self)

        # Set up the user interface from Qt Designer
        self.setupUi(self)

        # Fill the table with available devices
        self.devices = Devices()
        self.deviceTable.setRowCount(len(self.devices))

        # No device selected by default
        self.selectedDevice = None

        for n in range(0, len(self.devices)):
            item = QTableWidgetItem(self.devices[n].blockDevice())
            self.deviceTable.setItem(n, 0, item)
            item = QTableWidgetItem(self.devices[n].model())
            self.deviceTable.setItem(n, 1, item)
            item = QTableWidgetItem(str(self.devices[n].size()))
            self.deviceTable.setItem(n, 2, item)
            item = QTableWidgetItem(self.devices[n].serialNumber())
            self.deviceTable.setItem(n, 3, item)

        self.deviceTable.horizontalHeader().setStretchLastSection(True)
        self.deviceTable.resizeColumnsToContents()

        self.connect(self.deviceTable, SIGNAL("clicked(const QModelIndex&)"), self.setDevice)
        self.connect(self.deviceTable, SIGNAL("doubleClicked(const QModelIndex&)"), self.rowSelected)

    def rowSelected(self, modelIndex):
        self.setDeviceAndAccept(modelIndex.row())

    def setDeviceAndAccept(self, row):
        self.selectedDevice = self.devices[row]
        self.accept()

    def setDevice(self, modelIndex):
        self.selectedDevice = self.devices[modelIndex.row()]
