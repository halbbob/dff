# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2010 ArxSys
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
#  Frederic Baguelin <fba@digital-forensic.org>
# 

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import Qt, QSize, QString, SIGNAL, QThread
from PyQt4.QtGui import QPixmap, QImage, QPushButton, QLabel, QWidget, QHBoxLayout, QVBoxLayout, QScrollArea, QIcon, QMatrix, QToolBar, QAction, QSizePolicy, QTabWidget, QTableWidget, QTableWidgetItem

from api.vfs import *
from api.module.module import *
from api.module.script import *
from api.magic.filetype import FILETYPE

import sys
import time
import re

import EXIF

class LoadedImage(QLabel):
  def __init__(self, parent):
    QLabel.__init__(self)
    self.parent = parent
    self.baseImage = QImage()
    self.matrix = QMatrix()
    self.zoomer = 1
    self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Ignored);
    self.setScaledContents(True);
    

  def setParent(self, parent):
    self.parent = parent


  def load(self, node):
    self.node = node
    file = self.node.open()
    buff = file.read()
    file.close()
    self.baseImage.loadFromData(buff)
    self.curWidth = self.parent.width() - 10
    self.curHeight = self.parent.height() - 10
    self.adjust()


  def adjust(self):
    if self.zoomer == 1:
      self.curWidth = self.parent.width() - 10
      self.curHeight = self.parent.height() - 10
    self.updateTransforms()


  def updateTransforms(self):
    if self.zoomer == 1:
      if self.curWidth > self.curHeight:
        self.currentImage = self.baseImage.transformed(self.matrix).scaledToHeight(self.curHeight, Qt.FastTransformation)
      else:
        self.currentImage = self.baseImage.transformed(self.matrix).scaledToWidth(self.curWidth, Qt.FastTransformation)
    else:
      self.currentImage = self.baseImage.transformed(self.matrix).scaled(QSize(self.curWidth, self.curHeight), Qt.KeepAspectRatio, Qt.FastTransformation)
    self.setPixmap(QPixmap.fromImage(self.currentImage))
    self.adjustSize()
    

  def rotateLeft(self):
    self.matrix.rotate(-90)
    self.updateTransforms()


  def rotateRight(self):
    self.matrix.rotate(90)
    self.updateTransforms()


  def enlarge(self):
    self.zoomer *= 1.25
    self.curWidth *= 1.25
    self.curHeight *= 1.25
    self.updateTransforms()


  def shrink(self):
    self.zoomer *= 0.8
    self.curWidth *= 0.8
    self.curHeight *= 0.8
    self.updateTransforms()


  def fit(self):
    self.zoomer = 1
    self.curWidth = self.parent.width() - 10
    self.curHeight = self.parent.height() - 10
    self.updateTransforms()


  def normal(self):
    self.curWidth = self.baseImage.width()
    self.curHeight = self.baseImage.height()
    self.updateTransforms()


class Metadata(QTabWidget):
  def __init__(self):
    QTabWidget.__init__(self)
    self.setTabPosition(QTabWidget.East)


  def process(self, node):
    for idx in xrange(0, self.count()):
      widget = self.widget(idx)
      del widget
    self.clear()
    self.node = node
    file = self.node.open()
    tags = EXIF.process_file(file)
    sortedTags = {}
    for tag in tags.keys():
      if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
        spaceidx = tag.find(" ")
        ifd = tag[:spaceidx].strip()
        if ifd == "Image":
          ifd = "IFD 0 (Image)"
        if ifd == "Thumbnail":
          ifd = "IFD 1 (Thumbnail)"
        key = tag[spaceidx:].strip()
        try:
          val = str(tags[tag])
        except:
          val = "cannot be decoded"
        if ifd not in sortedTags.keys():
          sortedTags[ifd] = []
        sortedTags[ifd].append((key, val))
    for ifd in sortedTags.keys():
      table = QTableWidget(len(sortedTags[ifd]), 2)
      table.setShowGrid(False)
      table.setAlternatingRowColors(True)
      table.verticalHeader().hide()
      table.horizontalHeader().setClickable(False)
      table.horizontalHeader().setStretchLastSection(True)
      table.setHorizontalHeaderLabels(["Tag", "Value"])
      self.addTab(table, ifd)
      row = 0
      for res in sortedTags[ifd]:
        key = QTableWidgetItem(res[0])
        val = QTableWidgetItem(res[1])
        table.setItem(row, 0, key)
        table.setItem(row, 1, val)
        row += 1
    if 'JPEGThumbnail' in tags.keys():
      label = QLabel()
      img = QImage()
      img.loadFromData(tags['JPEGThumbnail'])
      label.setPixmap(QPixmap.fromImage(img))
      label.setAlignment(Qt.AlignCenter)
      self.addTab(label, "Embedded Thumbnail")
    if 'TIFFThumbnail' in tags.keys():
      label = QLabel()
      img = QImage()
      img.loadFromData(tags['TIFFThumbnail'])
      label.setPixmap(QPixmap.fromImage(img))
      label.setAlignment(Qt.AlignCenter)
      self.addTab(label, "Embedded Thumbnail")


class ImageView(QWidget, Script):
  def __init__(self):
    Script.__init__(self, "viewerimage")
    self.type = "imageview"
    self.icon = None
    self.vfs = vfs.vfs()
    self.ft = FILETYPE()
    self.reg_viewer = re.compile(".*(JPEG|JPG|jpg|jpeg|GIF|gif|bmp|BMP|png|PNG|pbm|PBM|pgm|PGM|ppm|PPM|xpm|XPM|xbm|XBM).*", re.IGNORECASE)
    self.sceneWidth = 0


  def start(self, args):
    self.images = []
    node = args.get_node("file")
    children = node.parent().children()
    for child in children:
      if self.isImage(child):
        self.images.append(child)
        if child.name() == node.name():
          self.curIdx = len(self.images)


  def isImage(self, node):
    if node.size() != 0:
      try:
        #XXX temporary patch for windows magic
        f = str(node.staticAttributes().attributes()["type"])
      except (IndexError, AttributeError):
        #XXX temporary patch for windows magic
        self.ft.filetype(node)
        f = str(node.staticAttributes().attributes()["type"])
    res = self.reg_viewer.match(str(f))
    if res != None:
      return True
    return False


  def next(self):
    if self.curIdx == len(self.images):
      self.curIdx = 0
    else:
      self.curIdx += 1
    self.setImage(self.images[self.curIdx])


  def previous(self):
    if self.curIdx == 0:
      self.curIdx = len(self.images)
    else:
      self.curIdx -= 1
    self.setImage(self.images[self.curIdx])
      

  def createActions(self):
    self.actions = QToolBar()
    self.actions.setObjectName("Image viewer actions")
    self.nextButton = QAction(QIcon(":next.png"), "Display next image", self.actions)
    self.previousButton = QAction(QIcon(":previous.png"), "Display previous image", self.actions)
    self.rotlButton = QAction(QIcon(":rotate-left.png"), "Rotate the image 90 degrees to the left", self.actions)
    self.rotrButton = QAction(QIcon(":rotate-right.png"), "Rotate the image 90 degrees to the right", self.actions)
    self.enlargeButton = QAction(QIcon(":viewmag+"), "Enlarge the image", self.actions)
    self.shrinkButton = QAction(QIcon(":viewmag-"), "Shrink the image", self.actions)
    self.fitButton = QAction(QIcon(":viewmagfit"), "Fit the image to the window", self.actions)
    self.normalButton = QAction(QIcon(":viewmag1"), "Show the image at its normal size", self.actions)
    self.actions.addAction(self.previousButton)
    self.actions.addAction(self.nextButton)
    self.actions.addAction(self.rotlButton)
    self.actions.addAction(self.rotrButton)
    self.actions.addAction(self.enlargeButton)
    self.actions.addAction(self.shrinkButton)
    self.actions.addAction(self.fitButton)
    self.actions.addAction(self.normalButton)
    self.connect(self.previousButton, SIGNAL("triggered()"), self.previous)
    self.connect(self.nextButton, SIGNAL("triggered()"), self.next)
    self.connect(self.rotlButton, SIGNAL("triggered()"), self.loadedImage.rotateLeft)
    self.connect(self.rotrButton, SIGNAL("triggered()"), self.loadedImage.rotateRight)
    self.connect(self.enlargeButton, SIGNAL("triggered()"), self.loadedImage.enlarge)
    self.connect(self.shrinkButton, SIGNAL("triggered()"), self.loadedImage.shrink)
    self.connect(self.fitButton, SIGNAL("triggered()"), self.loadedImage.fit)
    self.connect(self.normalButton, SIGNAL("triggered()"), self.loadedImage.normal)


  def setImage(self, node):
    self.loadedImage.load(node)
    self.metadata.process(node)


  def g_display(self):
    QWidget.__init__(self, None)
    self.factor = 1
    self.vbox = QVBoxLayout()
    self.setLayout(self.vbox)
    self.metadata = Metadata()
    self.scrollArea = QScrollArea()
    self.loadedImage = LoadedImage(self.scrollArea)
    self.scrollArea.setWidget(self.loadedImage)
    self.scrollArea.setAlignment(Qt.AlignCenter)
    self.createActions()
    self.vbox.addWidget(self.actions)
    self.hbox = QHBoxLayout()
    self.vbox.addLayout(self.hbox)
    self.hbox.addWidget(self.scrollArea)
    self.hbox.addWidget(self.metadata)
    self.vbox.setAlignment(self.actions, Qt.AlignCenter)
    self.setImage(self.images[self.curIdx])


  def updateWidget(self):
    self.metadata.setMaximumSize(self.width() / 4, self.height())
    self.loadedImage.adjust()


  def resizeEvent(self, e):
    self.metadata.setMaximumSize(self.width() / 4, self.height())
    self.loadedImage.adjust()


class viewerimage(Module):
  """Display content of graphic file"""
  def __init__(self):
    Module.__init__(self, "viewerimage", ImageView)
    self.conf.add("file", "node", False, "File to display")
    self.conf.add_const("mime-type", "JPEG")
    self.conf.add_const("mime-type", "GIF")
    self.conf.add_const("mime-type", "PNG")
    self.conf.add_const("mime-type", "BMP")
    self.tags = "viewer"
