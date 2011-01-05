from PyQt4.QtGui import QFileDialog, QMessageBox, QInputDialog, QTableWidget, QTableWidgetItem, QDialog, QHBoxLayout, QPushButton, QVBoxLayout, QSplitter, QDialogButtonBox, QFormLayout, QWidget, QComboBox, QLabel, QPixmap
from PyQt4.QtCore import QString, Qt, SIGNAL, SLOT

from api.taskmanager import *
from api.taskmanager.taskmanager import * 
from api.loader import *
from api.vfs import vfs
from api.devices.devices import Devices


class DevicesDialog(QDialog):
  def __init__(self, parent = None):
    QDialog.__init__(self)

    self.selectedDevice = None
    
    self.setWindowTitle("Add local device")
    self.listdevices = {}
    self.vbox = QVBoxLayout()
    self.dcontainer = QWidget()
    self.devicebuttonbox = QDialogButtonBox()

    ok = QPushButton("OK", self)
    self.connect(ok, SIGNAL("clicked()"), SLOT("accept()"))
    cancel = QPushButton("Cancel", self)
    self.connect(cancel, SIGNAL("clicked()"), SLOT("reject()"))
    self.devicebuttonbox.addButton(ok, QDialogButtonBox.AcceptRole)
    self.devicebuttonbox.addButton(cancel, QDialogButtonBox.RejectRole)
    
    self.combodevice = QComboBox()
        # Get devices and add in combobox
    self.devices = Devices()
    for n in range(0, len(self.devices)):
      print "N : ", n
      self.combodevice.addItem(self.devices[n].model())
      self.listdevices[n] = self.devices[n]

    self.connect(self.combodevice, SIGNAL("currentIndexChanged(int)"), self.deviceChanged) 

    self.setDeviceInformations(self.devices[0], True)
    self.selectedDevice = self.devices[0]

    self.header = QHBoxLayout()
    self.pix = QPixmap(":dev_hd.png")
    self.pixlabel = QLabel()
    self.pixlabel.setPixmap(self.pix.scaledToWidth(48))

    self.header.addWidget(self.pixlabel)
    self.title = QLabel("Select a local device to add in the VFS")
    self.header.addWidget(self.title)

    self.plabel = QLabel("<font color='red'>Warning ! You must be administrator</font>")

    self.formLayout = QFormLayout()
    self.formLayout.addRow(self.header)
    self.formLayout.addRow(self.plabel)
    self.formLayout.addRow("Select device :", self.combodevice)
    self.formLayout.addRow("Block device :", self.blockdevice)
    self.formLayout.addRow("Model :", self.model)
    self.formLayout.addRow("Size :", self.size)

    self.dcontainer.setLayout(self.formLayout)

    self.vbox.addWidget(self.dcontainer)
    self.vbox.addWidget(self.devicebuttonbox)

    self.setLayout(self.vbox)

  def setDeviceInformations(self, device, init=False):
    if init:
      self.blockdevice = QLabel(str(device.blockDevice()))
      self.model = QLabel(str(device.model()))
      self.serial = QLabel(str(device.serialNumber()))
      self.size = QLabel(str(device.size()))
    else:
      self.blockdevice.setText(str(device.blockDevice()))
      self.model.setText(str(device.model()))
      self.serial.setText(str(device.serialNumber()))
      self.size.setText(str(device.size()))
      
  def deviceChanged(self, index):
    self.setDeviceInformations(self.listdevices[index])
    self.selectedDevice = self.listdevices[index]

############ OLD #####################"


class OldDevicesDialog(QDialog):
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
       self.setItem(n, 3, self.item(QString(str(self.devices[n].size()))))

     self.horizontalHeader().setStretchLastSection(True)
     self.resizeColumnsToContents()

  def item(self, val):
      item = QTableWidgetItem(QString(val))
      item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)	 
      return item	
#   def update(self): #update device liste
