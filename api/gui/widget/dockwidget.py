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
# 

from PyQt4.QtGui import QDockWidget
from PyQt4.QtCore import Qt

class DockWidget(QDockWidget):
  def __init__(self, mainWindow, widget, name):
    QDockWidget.__init__(self, mainWindow)
    self.init(widget, name)
    self.show()
    self.setObjectName(name)

  def init(self, widget, name):
    self.setAllowedAreas(Qt.AllDockWidgetAreas)
    self.setWindowTitle(name)
    self.setWidget(widget)
 

