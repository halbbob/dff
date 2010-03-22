from PyQt4.QtGui import QDockWidget
from PyQt4.QtCore import Qt

class DockWidget(QDockWidget):
  def __init__(self, mainWindow, widget, name):
    QDockWidget.__init__(self, mainWindow)
    self.init(widget, name)
    self.show()

  def init(self, widget, name):
    self.setAllowedAreas(Qt.AllDockWidgetAreas)
    self.setWindowTitle(name)
    self.setWidget(widget)
 

