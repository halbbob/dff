import os

from PyQt4.QtGui import QFileDialog, QMessageBox, QInputDialog
from PyQt4.QtCore import QObject

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

  def addDumps(self):
       """Choose to add a device or a file"""
       items = [self.tr("Device"), self.tr("File")]
       res = QInputDialog.getItem(self.parent, self.tr("Add dump:"), self.tr("Choose dump type:"), items, 0, False) 
       type = res[0] 
       ok = res[1]
       if ok:
	 if type == self.tr("Device"):
	    self.addDevices()
         elif type == self.tr("File"):
	    self.addFiles()

  def addDevices(self):
       """Open a device list dialog"""
       dev = DevicesDialog(self.parent)
       if dev.exec_():
	 if dev.selectedDevices:
           arg = self.env.libenv.argument("gui_input")
           arg.thisown = 0
	   arg.add_path("path", str(dev.selectedDevices.blockDevice())) 
           arg.add_node("parent", self.vfs.getnode("/"))
           arg.add_uint64("size", long(dev.selectedDevices.size())) 
	   exec_type = ["thread", "gui"]
           self.taskmanager.add("local", arg, exec_type)

  def addFiles(self):
        """ Open a Dialog for select a file and add in VFS """
        sFileName = QFileDialog.getOpenFileNames(self.parent, self.tr("Add Dumps"),  os.path.expanduser('~'))
        for name in sFileName:
            arg = self.env.libenv.argument("gui_input")
            arg.thisown = 0
	    arg.add_path("path", str(name))
            arg.add_node("parent", self.vfs.getnode("/"))
	    exec_type = ["thread", "gui"]
            self.taskmanager.add("local", arg, exec_type)
 
  def loadDriver(self):
        sFileName = QFileDialog.getOpenFileName(self.parent, self.tr("Load module"),  os.path.expanduser('~'),  "Modules(*.py)")
        if (sFileName) :
            self.loader.do_load(str(sFileName))

  def about(self):
        """ Open a About Dialog """
        QMessageBox.information(self.parent, self.tr("About"),   self.tr("<b>Digital Forensics Framework</b> (version 0.8)<br><br> If you have any troubles, please visit our <a href=\"http://wiki.digital-forensic.org/\">support page</a>.<br>IRC channel: <a href=\"https://webchat.freenode.net/?channels=digital-forensic\">#digital-forensic</a> on Freenode network.<br>More information: <a href=\"http://www.digital-forensic.org/\">www.digital-forensic.org</a>.<br><br>Software developed by <a href=\"http://arxsys.fr/\">ArxSys</a> and <a href=\"https://tracker.digital-forensic.org/\">the DFF community</a>."))
