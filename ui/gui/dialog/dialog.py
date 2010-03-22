import os

from PyQt4.QtGui import QFileDialog, QMessageBox 

from api.taskmanager import *
from api.taskmanager.taskmanager import * 
from api.loader import *

class Dialog():
  def __init__(self, parent):
     self.parent = parent 
     self.env = env.env()
     self.taskmanager = TaskManager()
     self.loader = loader.loader()

  def addDumps(self):
        """ Open a Dialog for select a file and add in VFS """
        sFileName = QFileDialog.getOpenFileNames(self.parent, "Add Dumps",  os.path.expanduser('~'))
        for name in sFileName:
            arg = self.env.libenv.argument("gui_input")
            arg.thisown = 0
            arg.add_node("parent",  self.parent.widget["NodeTree"].treeItemModel.rootItem.node)
	    arg.add_path("path", str(name))
	    exec_type = ["thread", "gui"]
            self.taskmanager.add("local", arg, exec_type)
 
  def loadDriver(self):
        sFileName = QFileDialog.getOpenFileName(self.parent, "Load module",  os.path.expanduser('~'),  "Modules(*.py)")
        if (sFileName) :
            self.loader.do_load(str(sFileName))

  def about(self):
        """ Open a About Dialog """
        QMessageBox.information(self.parent, "About",   "<b>Digital Forensics Framework</b> (version 0.5)<br><br> If you have any troubles, please visit our <a href=\"http://wiki.digital-forensic.org\"> support page</a><br>IRC channel: freenode #digital-forensic<br>More information: <a href=\"ht\
tp://www.digital-forensic.org\"> digital-forensic </a><br><br>Software developed by <a href=\"http://arxsys.fr\"> ArxSys</a>")
 
