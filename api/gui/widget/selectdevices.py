from PyQt4.QtGui import QFileDialog, QMessageBox, QInputDialog, QTableWidget, QTableWidgetItem, QDialog, QHBoxLayout, QPushButton, QVBoxLayout, QSplitter
from PyQt4.QtCore import QString, Qt, SIGNAL, SLOT

from api.taskmanager import *
from api.taskmanager.taskmanager import * 
from api.loader import *
from api.vfs import vfs
from api.devices.devices import Devices


class DevicesDialog(QDialog):
  def __init__(self, parent = None):
     QDialog.__init__(self)
     self.deviceTable = SelectDevices(self)
     self.hlayout = QSplitter(self) 
     self.vlayout = QVBoxLayout(self)
     self.vlayout.addWidget(self.deviceTable) 
     self.setLayout(self.vlayout)
     self.vlayout.setStretchFactor(self.hlayout, 1) #?
     self.selectedDevices = None

     ok = QPushButton("OK", self)
     self.connect(ok, SIGNAL("clicked()"), SLOT("accept()"))
     self.hlayout.addWidget(ok)

     cancel = QPushButton("Cancel", self)
     self.connect(cancel, SIGNAL("clicked()"), SLOT("reject()"))
     self.hlayout.addWidget(cancel)
     self.vlayout.insertWidget(1, self.hlayout)

     self.setMinimumSize(self.deviceTable.size()) 
     self.connect(self.deviceTable, SIGNAL("cellClicked(int,int)"), self.setDevices)

  def setDevices(self, row, column):
      self.selectedDevices = self.deviceTable.devices[row]

class SelectDevices(QTableWidget):
  def __init__(self, parent = None):
     self.devices = Devices()
     QTableWidget.__init__(self)
     self.setColumnCount(4)
     self.setRowCount(len(self.devices))	   
     self.verticalHeader().hide()

     self.setHorizontalHeaderItem(0, QTableWidgetItem(QString("Serial number"))) 
     self.setHorizontalHeaderItem(1, QTableWidgetItem(QString("Device"))) 
     self.setHorizontalHeaderItem(2, QTableWidgetItem(QString("Model"))) 
     self.setHorizontalHeaderItem(3, QTableWidgetItem(QString("Size"))) 
 
     for n in range(0, len(self.devices)):
       item = QTableWidgetItem
       self.setItem(n, 0, self.item(self.devices[n].serialNumber()))
       self.setItem(n, 1, self.item(self.devices[n].blockDevice())) 
       self.setItem(n, 2, self.item(self.devices[n].model()))
       self.setItem(n, 3, self.item(str(self.devices[n].size())))

     self.horizontalHeader().setStretchLastSection(True)
     self.resizeColumnsToContents()

  def item(self, val):
      item = QTableWidgetItem(QString(val))
      item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)	 
      return item	
#   def update(self): #update device liste
