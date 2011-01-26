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
#  Jeremy MOUNIER <jmo@digital-forensic.org>
# 

from PyQt4.QtGui import QDockWidget
from PyQt4.QtCore import Qt, SIGNAL

class DockWidget(QDockWidget):
  def __init__(self, mainWindow, widget, name):
    QDockWidget.__init__(self, mainWindow)
    self.mainwindow = mainWindow
    self.init(widget)
    self.show()
    self.setObjectName(name)

  def init(self, widget):
    self.name = widget.name
    self.setAllowedAreas(Qt.AllDockWidgetAreas)
    self.setFeatures(QDockWidget.AllDockWidgetFeatures)
    self.setWidget(widget)

    self.connect(self, SIGNAL("topLevelChanged(bool)"), self.toplevel_changed)
 
  def toplevel_changed(self, state):
    if not state:
      self.mainwindow.refreshTabifiedDockWidgets()

  def visibility_changed(self, enable):
    if enable:
      self.raise_()
      self.setFocus()
