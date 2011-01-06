import os

from PyQt4.QtGui import QFileDialog, QMessageBox, QInputDialog, QDialog, QDialogButtonBox, QComboBox, QPushButton, QFormLayout, QHBoxLayout, QPixmap, QLabel
from PyQt4.QtCore import QObject, QString, SIGNAL, SLOT, Qt

from api.taskmanager import *
from api.taskmanager.taskmanager import * 
from api.loader import *
from api.vfs import vfs
from api.devices.devices import Devices
from api.gui.widget.selectdevices import DevicesDialog 

class Dialog(QObject):
  def __init__(self, parent):
     QObject.__init__(self)
     self.parent = parent 
     self.env = env.env()
     self.vfs = vfs.vfs()
     self.taskmanager = TaskManager()
     self.loader = loader.loader()

  def addDevices(self):
       """Open a device list dialog"""
       dev = DevicesDialog(self.parent)
       if dev.exec_():
	 if dev.selectedDevice:
           arg = self.env.libenv.argument("gui_input")
           arg.thisown = 0
	   arg.add_path("path", str(dev.selectedDevice.blockDevice())) 
           arg.add_node("parent", self.vfs.getnode("/"))
           arg.add_uint64("size", long(dev.selectedDevice.size())) 
	   exec_type = ["thread", "gui"]
           if os.name == "nt":
             arg.add_string("name", str(dev.selectedDevice.model()))	   
             self.taskmanager.add("windevices", arg, exec_type)	
           else:	   
             self.taskmanager.add("local", arg, exec_type)

  def addFiles(self):
        """ Open a Dialog for select a file and add in VFS """
        edialog = evidenceDialog(self.parent)
        ir = edialog.exec_()
        if ir > 0:
          dtype = edialog.comboformat.currentText()
          # RAW files # EWF files # Local directory
          if dtype == "Local directory":
            sFiles = QFileDialog.getExistingDirectory(self.parent, self.tr("Add evidence directory"), os.path.expanduser('~'))
          elif dtype == "EWF files" or dtype == "RAW files":
            sFiles = QFileDialog.getOpenFileNames(self.parent, self.tr("Add evidence files"),  os.path.expanduser('~'))

          if len(sFiles) > 0:
            if dtype != "Local directory":
              for name in sFiles:
                arg = self.env.libenv.argument("gui_input")
                arg.thisown = 0
                exec_type = ["thread", "gui"]
                if dtype == "EWF files":
                  arg.add_path("file", str(name))
                  self.taskmanager.add("ewf", arg, exec_type)
                else:
                  arg.add_path("path", str(name))
                  arg.add_node("parent", self.vfs.getnode("/"))
                  self.taskmanager.add("local", arg, exec_type)
          else:
            arg = self.env.libenv.argument("gui_input")
            arg.thisown = 0
            exec_type = ["thread", "gui"]
            arg.add_path("path", str(sFiles))
            arg.add_node("parent", self.vfs.getnode("/"))
            self.taskmanager.add("local", arg, exec_type)
 
  def loadDriver(self):
        sFileName = QFileDialog.getOpenFileName(self.parent, self.tr("Load module"),  os.path.expanduser('~'),  "Modules(*.py)")
        if (sFileName) :
            self.loader.do_load(str(sFileName))

  def about(self):
        """ Open a About Dialog """
        QMessageBox.information(self.parent, self.tr("About"),   self.tr("<b>Digital Forensics Framework</b> (version 0.9)<br><br> If you have any troubles, please visit our <a href=\"http://wiki.digital-forensic.org/\">support page</a>.<br>IRC channel: <a href=\"https://webchat.freenode.net/?channels=digital-forensic\">#digital-forensic</a> on Freenode network.<br>More information: <a href=\"http://www.digital-forensic.org/\">www.digital-forensic.org</a>.<br><br>Software developed by <a href=\"http://arxsys.fr/\">ArxSys</a> and <a href=\"https://tracker.digital-forensic.org/\">the DFF community</a>."))


class evidenceDialog(QDialog):
  def __init__(self, parent):
    QDialog.__init__(self, parent)
    self.createShape()

  def createShape(self):
    # Futur : Get all DFF connectors
    self.setWindowTitle("Select evidence type")
    self.buttonbox = QDialogButtonBox()
    ok = QPushButton("OK", self)
    self.connect(ok, SIGNAL("clicked()"), SLOT("accept()"))
    cancel = QPushButton("Cancel", self)
    self.connect(cancel, SIGNAL("clicked()"), SLOT("reject()"))
    self.buttonbox.addButton(ok, QDialogButtonBox.AcceptRole)
    self.buttonbox.addButton(cancel, QDialogButtonBox.RejectRole)

    self.comboformat = QComboBox()
        # Get devices and add in combobox
    self.comboformat.addItem("RAW files")
    self.comboformat.addItem("EWF files")
    self.comboformat.addItem("Local directory")

    self.header = QHBoxLayout()
    self.header.setAlignment(Qt.AlignLeft)
    self.pix = QPixmap(":add_image.png")
    self.pixlabel = QLabel()
    self.pixlabel.setPixmap(self.pix.scaledToWidth(48))

    self.header.addWidget(self.pixlabel)
    self.title = QLabel("Select data type to open in the VFS")
    self.header.addWidget(self.title)

    self.formLayout = QFormLayout()
    self.formLayout.addRow(self.header)
    self.formLayout.addRow("Data type :", self.comboformat)
    self.formLayout.addRow(self.buttonbox)

    self.setLayout(self.formLayout)


    

  

