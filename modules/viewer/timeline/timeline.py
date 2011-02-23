# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
# 
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
#  Christophe Malinge <cma@digital-forensic.org>
#

# System imports
from datetime import timedelta
from PyQt4.QtCore import QDateTime, Qt, QPointF, QRectF, SIGNAL, QString
from PyQt4.QtGui import QPixmap, QColor, QWidget, QVBoxLayout, QSplitter, QPainter

# DFF imports
from api.vfs import vfs
from api.module.module import Module
from api.module.script import Script

# Timeline imports
from dffdatetime import DffDatetime
from paint_area import PaintArea
from options_layout import OptionsLayout
from compute_thread import WorkerThread, CountThread, MaxOccThread
from list_thread import DataThread
from drawer import Drawer
from api.types.libtypes import Argument, typeId

class Timeline(QWidget, Script):
  def __init__(self):
    Script.__init__(self, 'timeline')
    QWidget.__init__(self, None)
    self.type = 'timeline'
    self.nodeCount = 0
    self.timesCount = 0
    self.timeMap = {}
    self.m = 40 # Padding
    self.lineHeight = 4 # Pixel height of line
    self.metricOk = False
    self.colors = [['blue', Qt.blue], ['red', Qt.red],
                   ['green', Qt.green], ['yellow', Qt.yellow],
                   ['magenta', Qt.magenta], ['cyan', Qt.cyan]]
    self.stateinfo = 'Initialized'
    self.dateMin = DffDatetime(9999, 12, 31, 23, 59, 59, 999999)
    self.dateMax = DffDatetime(1, 1, 1)
    self.baseDateMin = self.dateMin
    self.baseDateMax = self.dateMax
    self.selDateMin = None
    self.selDateMax = None
    self.maxOcc = 0
    self.maxOccZoom = 0
    self.xHop = 0
    self.xRange = 0
    self.dataListsCreated = False

  def start(self, args):
    self.node = args['file'].value()
    
  def status(self):
    return 0

  def updateWidget(self):
    pass

  def g_display(self):
    self.name = 'timeline ' + QString(self.node.name())
    if not self.node.hasChildren():
        self.setStateInfo(self.node.absolute() + ' doesn\'t have any children.')
    else:
        self.vfs = vfs.vfs()

        self.vlayout = QVBoxLayout()
        self.vlayout.setMargin(0)
        self.vlayout.setSpacing(0)
        
        self.hsplitter = QSplitter()
        self.ploter = PaintArea(self)
        self.options = OptionsLayout(self)

        self.hsplitter.addWidget(self.ploter)
        self.hsplitter.addWidget(self.options)
        self.vlayout.addWidget(self.hsplitter)
        self.setLayout(self.vlayout)
        self.draw = Drawer(self)

        # CountThread compute node amount
        self.countThread = CountThread(self, self.countThreadOver)
        self.populateThread = DataThread(self, self.dataThreadOver)
        self.maxOccThread = MaxOccThread(self, self.maxOccThreadOver)
        self.workerThread = WorkerThread(self)

#comment it to avoid redraw everytime painter is resized
        self.connect(self.workerThread, SIGNAL('refresh'), self.reDraw)
        

  def fromUSec(self, usec2):
      usec = int(usec2)
      days = usec / (86400 * 1000000)
      seconds = (usec - days * 86400 * 1000000) / 1000000
      misec = usec - days * 86400 * 1000000 - seconds * 1000000
      if days >= 1 and DffDatetime.fromordinal(days) >= DffDatetime.fromordinal(1):
        return DffDatetime.fromordinal(days) + timedelta(seconds = seconds, microseconds = misec)
      return None


  def countThreadOver(self):
      if not self.nodeCount:
        self.setStateInfo('No timestamp found any subset of ' + self.node.absolute())
#        self.disconnect(self.workerThread, SIGNAL('refresh'), self.reDraw)
        return
      self.setStateInfo(str(self.nodeCount) + ' nodes found')

# Find/virtual draw maximum size of Y text
      painter = QPainter()
      nullPixmap = QPixmap(self.ploter.width, self.ploter.height)
      painter.begin(nullPixmap)
      rect = painter.drawText(self.draw.paddingYText, 10, 0, 0, 0, str(self.nodeCount) + '.0')
      painter.end()
      self.draw.yLeftMargin = self.draw.paddingYText * 2 + rect.width()
      
      self.options.newInformations()
      self.options.createMetricTools()
      self.metricOk = True
#     self.createFullTimeLists()
      self.workerThread.render()

  def createFullTimeLists(self):
    self.populateThread = DataThread(self, self.dataThreadOver)
    self.populateThread.start()

  def dataThreadOver(self):
      self.dataListsCreated = True
      for family in self.options.configuration:
        # family[0] = extended|static|usual
        for time in family[1]:
          if time[1][5][1]:
              dateMin = time[1][6][1][0]
              dateMax = time[1][6][1][1]
              if dateMin < self.baseDateMin:
                  self.baseDateMin = dateMin
              if dateMax > self.baseDateMax:
                  self.baseDateMax = dateMax
      self.options.newInformations()
      self.workerThread.render()


  def findMaxValue(self):
      self.xRange = (self.ploter.width - self.m - self.draw.yLeftMargin) / self.lineHeight
      self.xHop = (self.baseDateMax.usec - self.baseDateMin.usec) / self.xRange

  def maxOccThreadOver(self):
      self.updatePaintingArea()

  def zoomMaxOcc(self):
    self.xRange = (self.ploter.width - self.m - self.draw.yLeftMargin) / self.lineHeight
    xHop = (self.selDateMax.usec - self.selDateMin.usec) / self.xRange
    newMaxOcc = 0
    for family in self.options.configuration:
      for time in family[1]:
        timeChecked = self.selDateMin.usec
        if timeChecked == self.selDateMax.usec:
# Every nodes have the same time, setting maxOcc computing time + 100usec
          occ = time[1][5][1].elementsInRange(self.fromUSec(timeChecked), self.fromUSec(timeChecked + 100), time[1][5][1])
          if occ > newMaxOcc:
              newMaxOcc = occ
        while timeChecked <= self.selDateMax.usec:
          occ = time[1][5][1].elementsInRange(self.fromUSec(timeChecked), self.fromUSec(timeChecked + xHop), time[1][5][1])
          if occ > newMaxOcc:
            newMaxOcc = occ
          timeChecked += xHop
              
    self.maxOccZoom = newMaxOcc

  def reDraw(self, resized = False):
    if resized:
      self.updatePaintingArea(True)
      
  def updatePaintingArea(self, resized = False):
      if not self.maxOcc:
          return
      
      self.painter = QPainter()

      self.mainPixmap = QPixmap(self.ploter.width, self.ploter.height)
      self.mainPixmap.fill(Qt.white)

      self.gridPixmap = QPixmap(self.ploter.width, self.ploter.height)
      self.gridPixmap.fill(Qt.transparent)

      self.painter.begin(self.gridPixmap)

      if self.options.zoom and not self.maxOccZoom:
        self.zoomMaxOcc()
        
      self.draw.setDynamicValues(self)
      self.draw.drawInfos()
      self.draw.drawGrid()

      self.painter.end()

      for family in self.options.configuration:
          for time in family[1]:
              if resized:
                time[1][8][1][0] = True
                time[1][7][1][0] = True

              if self.options.zoom and time[1][8][1][0]:
# Create zoom pixmaps
                  time[1][8][1][1] = QPixmap(self.ploter.width, self.ploter.height)
                  time[1][8][1][1].fill(Qt.transparent)
                  penColor = None
                  for color in self.colors:
                      if color[0] == time[1][1][1]:
                          penColor = QColor(color[1])
                          penColor.setAlpha(163)
                          break
                  if penColor:
                      self.painter.begin(time[1][8][1][1])
                      pen = self.painter.pen()
                      pen.setColor(penColor)
                      pen.setWidth(self.lineHeight)
                      self.painter.setPen(pen)
                      self.draw.drawTimeline(self.painter, time[1][5][1])
                      self.painter.end()
                      time[1][8][1][0] = False
                  
              elif not time[1][7][1][1] or time[1][7][1][0]:
# Create main (original sized) pixmaps
                  time[1][7][1][1] = QPixmap(self.ploter.width, self.ploter.height)
                  time[1][7][1][1].fill(Qt.transparent)
                  penColor = None
                  for color in self.colors:
                      if color[0] == time[1][1][1]:
                          penColor = QColor(color[1])
                          penColor.setAlpha(163)
                          break
                  if penColor:
                      self.painter.begin(time[1][7][1][1])
                      pen = self.painter.pen()
                      pen.setColor(penColor)
                      pen.setWidth(self.lineHeight)
                      self.painter.setPen(pen)
                      self.draw.drawTimeline(self.painter, time[1][5][1])
                      self.painter.end()
                      time[1][7][1][0] = False

      self.painter.begin(self.mainPixmap)
# Draw grid
      self.painter.drawImage(QPointF(0, 0), self.gridPixmap.toImage(), QRectF(0, 0, self.ploter.width, self.ploter.height))
      for family in self.options.configuration:
        for time in family[1]:
# Draw each time pixmap
          if not self.options.zoom:
# Draw global view, if zoom not enabled
            if time[1][7][1][1] and time[1][0][1]:
              self.painter.drawImage(QPointF(0, 0), time[1][7][1][1].toImage(), QRectF(0, 0, self.ploter.width, self.ploter.height))
          else:
# Draw zoom pixmaps
            if time[1][8][1][1] and time[1][0][1]:
              self.painter.drawImage(QPointF(0, 0), time[1][8][1][1].toImage(), QRectF(0, 0, self.ploter.width, self.ploter.height))

      self.painter.end()

      self.ploter.scene.clear()
      self.ploter.scene.addPixmap(self.mainPixmap)
      self.ploter.setEnabled(True)
      self.update()

      
  def setStateInfo(self, sinfo):
    self.stateinfo = str(sinfo)

  def stateInfo(self):
    if self.nodeCount:
        return self.stateinfo + ' - ' + str(self.nodeCount) + ' nodes'
    else:
        return self.stateinfo

  def nodesInRange(self, x1, x2):
    if not self.selDateMin:
      timeCheck = self.baseDateMin.usec
      timeMax = self.baseDateMax.usec
    else:
      timeCheck = self.selDateMin.usec
      timeMax = self.selDateMax.usec
    count = 0
    while timeCheck < timeMax:
      for family in self.options.configuration:
        for time in family[1]:
          occ = time[1][5][1].elementsInRange(self.fromUSec(timeCheck), self.fromUSec(timeCheck + self.xHop), time[1][5][1])
          if occ:
              if self.lineMatched(timeCheck, occ, x1, x2) and time[1][0][1]:
                count += occ

      timeCheck += self.xHop
    if count:
      self.options.zoomButton.setEnabled(True)
      self.options.exportButton.setEnabled(True)
      if count > 1:
        self.options.selectedNodes.setText(str(count) + ' time values selected')
      else:
        self.options.selectedNodes.setText('One time value selected')
    else:
      self.options.zoomButton.setEnabled(False)
      self.options.exportButton.setEnabled(False)
      self.options.selectedNodes.setText('Nothing selected')

  def lineMatched(self, usec, occ, x1, x2):
    if not self.selDateMin:
      dateMin = self.baseDateMin
      dateMax = self.baseDateMax
    else:
      dateMin = self.selDateMin
      dateMax = self.selDateMax

    if (dateMax - dateMin) > timedelta(0):
      x = ((usec - dateMin.usec) * (self.ploter.width - self.m - self.draw.yLeftMargin)) / (dateMax.usec - dateMin.usec) + self.draw.yLeftMargin
      if x <= self.draw.yLeftMargin:
        x += 3
      x_min = x - 2
      x_max = x + 2
      if x_min >= x1 and x_max <= x2:
        return True
    return False

class timeline(Module):
  """ Tachatte
  """
  def __init__(self):
    Module.__init__(self, 'timeline', Timeline)
    self.conf.addArgument({"name": "file",
                           "description": "Text file to display",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.tags = 'Statistics'
