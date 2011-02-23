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

from datetime import timedelta

from PyQt4.QtCore import Qt, QPoint, QLineF

from dffdatetime import DffDatetime

class Drawer():
  def __init__(self, timeline):
      self.timeline = timeline
      self.ploter = timeline.ploter
      self.options = timeline.options
      self.painter = None
      self.node = None
      self.m = timeline.m
      self.paddingYText = 4
      self.yLeftMargin = 0

  def setDynamicValues(self, timeline):
      self.painter = timeline.painter
      self.node = timeline.node
      self.baseDateMax = timeline.baseDateMax
      self.baseDateMin = timeline.baseDateMin
      self.selDateMin = timeline.selDateMin
      self.selDateMax = timeline.selDateMax
      self.maxOcc = timeline.maxOcc
      
  def drawGrid(self):
      """ Draw horizontal and vertical lines of grid

      yLeftMargin must be set, so call drawYInfos first.
      """
      pen = self.painter.pen()
      pen.setColor(Qt.black)
      pen.setStyle(Qt.SolidLine)
      self.painter.setPen(pen)
      # Draw X line
#      self.painter.drawLine(self.m,
      self.painter.drawLine(self.yLeftMargin,
                            self.ploter.height - self.m,
                            self.ploter.width - self.m,
                            self.ploter.height - self.m)
      # Draw Y line
#      self.painter.drawLine(self.m,
      self.painter.drawLine(self.yLeftMargin,
                            self.ploter.height - self.m,
#                            self.m,
                            self.yLeftMargin,
                            self.m / 3)

  def drawInfos(self):
    self.drawYInfos()
    self.drawXInfos()

  def drawXInfos(self):
    pen = self.painter.pen()
    i = 1
    scale = 6
    x = self.yLeftMargin
    y = self.ploter.height - self.m
    if not self.selDateMin:
      date = self.baseDateMin.usec
      shift_date = (self.baseDateMax.usec - self.baseDateMin.usec) / scale
    else:
      date = self.selDateMin.usec
      shift_date = (self.selDateMax.usec - self.selDateMin.usec) / scale
    while i <= scale + 1:
      pen.setColor(Qt.black)
      pen.setStyle(Qt.SolidLine)
      pos = QPoint(x - 40, y + 17)
      self.painter.setPen(pen)
# Draw vertical doted line
      self.painter.drawLine(x, y - 3, x, y + 3)
# Draw date
      self.painter.drawText(pos, str(self.timeline.fromUSec(date).strftime('%d.%m.%Y')))
# If number of days shown < scale, draw time
      if shift_date <= (86400 * 1000000):
        pos.setY(pos.y() + 15)
        pos.setX(pos.x() + 9)
# Draw time
        self.painter.drawText(pos, str(self.timeline.fromUSec(date).strftime('%H:%M:%S')))
      
      pen.setColor(Qt.gray)
      pen.setStyle(Qt.DotLine)
      self.painter.setPen(pen)
      if i != 1:
        self.painter.drawLine(x, y + 3, x, self.m / 3)
      x = self.yLeftMargin + (i * ((self.ploter.width - self.m - self.yLeftMargin) / (scale)))
      i += 1
      date += shift_date
    pen.setStyle(Qt.SolidLine)
    self.painter.setPen(pen)
    
  def drawYInfos(self):
    i = 1
    scale = 10.0
    y = self.m / 3

# Setting max occurence depending of zoom
    if not self.timeline.maxOccZoom:
      maxOcc = self.timeline.maxOcc
    else:
      maxOcc = self.timeline.maxOccZoom
      
# Draw Y legend
    i = 1
    y = self.m / 3
    pen = self.painter.pen()
    while i <= scale:
      pen.setColor(Qt.black)
      pen.setStyle(Qt.SolidLine)
      self.painter.setPen(pen)
      self.painter.drawLine(self.yLeftMargin - 3, y, self.yLeftMargin + 3, y)
      self.painter.drawText(self.paddingYText, y - 8, self.yLeftMargin - self.paddingYText * 2, 50, 0, str(maxOcc - (i - 1.0) * (maxOcc / scale)))
      pen.setColor(Qt.gray)
      pen.setStyle(Qt.DotLine)
      self.painter.setPen(pen)
      self.painter.drawLine(self.yLeftMargin + 3, y, self.ploter.width - self.m, y)
      y = (self.m / 3) + i * ((self.ploter.height - (self.m + self.m / 3)) / scale)
      i += 1

    pen.setStyle(Qt.SolidLine)
    self.painter.setPen(pen)

  def drawTimeline(self, painter, elements):
    self.painter = painter
# Find x drawing area
    xRange = (self.ploter.width - self.m - self.yLeftMargin) / self.timeline.lineHeight
# Find secs between each x hop
    if not self.timeline.selDateMin:
      self.xHop = (self.baseDateMax.usec - self.baseDateMin.usec) / xRange
    else:
# We are in a zoom
      self.xHop = (self.selDateMax.usec - self.selDateMin.usec) / xRange
# FIXME no need to set it for each line ...!
    self.timeline.xHop = self.xHop
    self.drawEverythingInX(elements)


  def drawEverythingInX(self, elements):
    if not self.timeline.selDateMin:
      timeChecked = self.baseDateMin.usec
      limit = self.baseDateMax.usec
    else:
      timeChecked = self.selDateMin.usec
      limit = self.selDateMax.usec
    while timeChecked <= limit:
      try:
        occ = elements.elementsInRange(self.timeline.fromUSec(timeChecked), self.timeline.fromUSec(timeChecked + self.xHop), elements)
      except:
        occ = 0
      if occ:
          self.drawOneLine(timeChecked, occ)
      timeChecked += self.xHop
      if self.xHop <= 0:
# FIXME ca a change...        self.timeline.res.add_const("error", "Not enough different date in this node")
        return
# FIXME ca a change aussi !    self.timeline.res.add_const("result", "no problem")
    return
    
  def drawOneLine(self, timeChecked, occ):
    if not self.timeline.selDateMin:
      dateMin = self.timeline.baseDateMin
      dateMax = self.timeline.baseDateMax
      maxOcc = self.timeline.maxOcc
    else:
      dateMin = self.timeline.selDateMin
      dateMax = self.timeline.selDateMax
      maxOcc = self.timeline.maxOccZoom

    if (dateMax - dateMin) > timedelta(0):
      x = ((timeChecked - dateMin.usec) * (self.ploter.width - self.m - self.yLeftMargin)) / (dateMax.usec - dateMin.usec) + self.yLeftMargin
      y = (((maxOcc - occ) * (self.ploter.height - self.m - (self.m / 3))) / maxOcc) + (self.m / 3)
      if x <= self.yLeftMargin:
          x += 3

      startY = self.ploter.height - self.m - 1
      endY = y

      if y < self.ploter.height - self.m - 1:
# Y level to show is biggest than penWidth
          startY -= 1
          endY -= 1

      if endY <= self.m / 3:
# Y level is biggest than Y max value
        endY = self.m / 3 + 2

      line = QLineF(x, startY, x, endY)

      self.painter.drawLines(line)

  def findXTime(self, x):
    self.selDateMin = self.timeline.selDateMin
    self.selDateMax = self.timeline.selDateMax
    usecX = 0
    if not self.selDateMin or not self.selDateMax:
# Click from main (original) view
      usecX = ((x - self.yLeftMargin) * (self.baseDateMax.usec - self.baseDateMin.usec)) / (self.ploter.width - self.m - self.yLeftMargin)
      usecX += self.baseDateMin.usec
      if usecX < self.baseDateMin.usec:
        usecX = self.baseDateMin.usec
      if usecX > self.baseDateMax.usec:
        usecX = self.baseDateMax.usec
# Avoid microseconds
      usecStr = str(int(usecX))
      usecX = int(usecStr[:-6] + '000000')
      ret = self.timeline.fromUSec(usecX)
      return DffDatetime(ret.year, ret.month, ret.day, ret.hour, ret.minute, ret.second, 0)
    else:
# Click already from a zoom view 
      usecX = ((x - self.yLeftMargin) * (self.selDateMax.usec - self.selDateMin.usec)) / (self.ploter.width - self.m - self.yLeftMargin)
      usecX += self.selDateMin.usec
      if usecX < self.selDateMin.usec:
        usecX = self.selDateMin.usec
      if usecX > self.selDateMax.usec:
        usecX = self.selDateMax.usec
# Avoid microseconds
      usecStr = str(int(usecX))
      usecX = int(usecStr[:-6] + '000000')
      ret = self.timeline.fromUSec(usecX)
      return DffDatetime(ret.year, ret.month, ret.day, ret.hour, ret.minute, ret.second, 0)
    return None
