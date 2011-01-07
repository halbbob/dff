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

    self.setWindowTitle(self.tr("Select Device"))
    self.listdevices = {}
    self.vbox = QVBoxLayout()
    self.dcontainer = QWidget()
    self.devicebuttonbox = QDialogButtonBox()

    ok = QPushButton(self.tr("OK"), self)
    self.connect(ok, SIGNAL("clicked()"), SLOT("accept()"))
    cancel = QPushButton(self.tr("Cancel"), self)
    self.connect(cancel, SIGNAL("clicked()"), SLOT("reject()"))
    self.devicebuttonbox.addButton(ok, QDialogButtonBox.AcceptRole)
    self.devicebuttonbox.addButton(cancel, QDialogButtonBox.RejectRole)
    
    self.combodevice = QComboBox()
        # Get devices and add in combobox
    self.devices = Devices()
    for n in range(0, len(self.devices)):
      self.combodevice.addItem(self.devices[n].model())
      self.listdevices[n] = self.devices[n]

    self.connect(self.combodevice, SIGNAL("currentIndexChanged(int)"), self.deviceChanged) 

    self.setDeviceInformations(self.devices[0], True)
    self.selectedDevice = self.devices[0]

    self.header = QHBoxLayout()
    self.header.setAlignment(Qt.AlignLeft)
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
    self.formLayout.addRow(self.tr("Select device:"), self.combodevice)
    self.formLayout.addRow(self.tr("Block device:"), self.blockdevice)
    self.formLayout.addRow(self.tr("Model:"), self.model)
    self.formLayout.addRow(self.tr("Serial:"), self.serial)
    self.formLayout.addRow(self.tr("Size:"), self.size)

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
