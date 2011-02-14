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
#  Frederic Baguelin <fba@digital-forensic.org>
# 

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import Qt, QSize, QString, SIGNAL, QThread
from PyQt4.QtGui import QPixmap, QImage, QPushButton, QLabel, QWidget, QHBoxLayout, QVBoxLayout, QScrollArea, QIcon, QMatrix, QToolBar, QAction, QSizePolicy, QTabWidget, QTableWidget, QTableWidgetItem, QAbstractItemView

from api.vfs import *
from api.module.module import *
from api.module.script import *
from modules.metadata.metaexif import EXIF
from api.types.libtypes import Argument, typeId

import sys
import time
import re

class LoadedImage(QLabel):
  def __init__(self, parent):
    QLabel.__init__(self)
    self.parent = parent
    self.baseImage = QImage()
    self.matrix = QMatrix()
    self.zoomer = 1
    self.maxsize = 1024*10*10*10*25
    self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Ignored);
    self.setAlignment(Qt.AlignCenter)
    #self.setScaledContents(True);
    

  def setParent(self, parent):
    self.parent = parent


  def load(self, node):
    self.matrix.reset()
    self.zoomer = 1
    if node.size() < self.maxsize:
       self.node = node
       file = self.node.open()
       buff = file.read()
       file.close()
       if self.baseImage.loadFromData(buff):
         self.emit(SIGNAL("available(bool)"), True)
       else:
         self.baseImage.load(":file_broken.png")
         self.emit(SIGNAL("available(bool)"), False)
    else:
      self.baseImage.loadFromData("")
      self.emit(SIGNAL("available(bool)"), False)
    self.adjust()


  def adjust(self):
    if self.zoomer == 1:
      if self.baseImage.width() < self.parent.width() - 10:
        self.curWidth = self.baseImage.width()
      else:
        self.curWidth = self.parent.width() - 10
      if self.baseImage.height() < self.parent.height() - 10:
        self.curHeight = self.baseImage.height()
      else:
        self.curHeight = self.parent.height() - 10
    self.updateTransforms()


  def updateTransforms(self):
    if not self.baseImage.isNull():
      self.currentImage = self.baseImage.transformed(self.matrix).scaled(QSize(self.curWidth, self.curHeight), Qt.KeepAspectRatio, Qt.FastTransformation)
      self.setPixmap(QPixmap.fromImage(self.currentImage))
    else:
      self.clear()
      self.setText("File is too big to be processed")
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
    self.adjust()


  def normal(self):
    self.curWidth = self.baseImage.width()
    self.curHeight = self.baseImage.height()
    self.updateTransforms()


class Metadata(QWidget):
  def __init__(self):
    QWidget.__init__(self)
    self.tabs = QTabWidget()
    self.nometa = QLabel("No EXIF metadata found")
    self.nometa.setAlignment(Qt.AlignCenter)
    self.box = QHBoxLayout()
    self.setLayout(self.box)
    self.box.addWidget(self.tabs)
    self.box.addWidget(self.nometa)
    self.nometa.hide()
    self.tabs.show()
    self.tabs.setTabPosition(QTabWidget.East)


  def process(self, node):
    for idx in xrange(0, self.tabs.count()):
      widget = self.tabs.widget(idx)
      del widget
    self.tabs.clear()
    self.node = node
    file = self.node.open()
    tags = EXIF.process_file(file)
    if len(tags) == 0:
      self.nometa.setSizePolicy(self.tabs.sizePolicy())
      self.tabs.hide()
      self.nometa.show()
    else:
      self.tabs.show()
      self.nometa.hide()
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
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tabs.addTab(table, ifd)
        row = 0
        for res in sortedTags[ifd]:
          key = QTableWidgetItem(res[0])
          key.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
          val = QTableWidgetItem(res[1])
          val.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
          table.setItem(row, 0, key)
          table.setItem(row, 1, val)
          row += 1
      if 'JPEGThumbnail' in tags.keys():
        label = QLabel()
        img = QImage()
        img.loadFromData(tags['JPEGThumbnail'])
        label.setPixmap(QPixmap.fromImage(img))
        label.setAlignment(Qt.AlignCenter)
        self.tabs.addTab(label, "Embedded Thumbnail")
      if 'TIFFThumbnail' in tags.keys():
        label = QLabel()
        img = QImage()
        img.loadFromData(tags['TIFFThumbnail'])
        label.setPixmap(QPixmap.fromImage(img))
        label.setAlignment(Qt.AlignCenter)
        self.tabs.addTab(label, "Embedded Thumbnail")


class ImageView(QWidget, Script):
  def __init__(self):
    Script.__init__(self, "viewerimage")
    self.type = "imageview"
    self.icon = None
    self.vfs = vfs.vfs()
    #self.ft = FILETYPE()
    self.reg_viewer = re.compile(".*(JPEG|JPG|jpg|jpeg|GIF|gif|bmp|png|PNG|pbm|PBM|pgm|PGM|ppm|PPM|xpm|XPM|xbm|XBM).*", re.IGNORECASE)
    self.sceneWidth = 0


  def start(self, args):
    self.images = []
    try:
      node = args["file"]
      children = node.parent().children()
      for child in children:
        if self.isImage(child):
          self.images.append(child)
          if child.name() == node.name():
            self.curIdx = len(self.images) - 1
    except KeyError:
      pass

  def isImage(self, node):
    if node.size() != 0:
      try:
        #XXX temporary patch for windows magic
        #f = str(node.staticAttributes().attributes()["mime-type"])
        type = node.dataType()
      except (IndexError, AttributeError, IOError):
        #XXX temporary patch for windows magic
        #self.ft.filetype(node)
	return False
        #f = str(node.staticAttributes().attributes()["mime-type"]) #XXX me pas tres verifier avec datatype fix vite fait
      if  self.reg_viewer.search(str(type)):
           return True
    return False


  def next(self):
    if self.curIdx == len(self.images) - 1:
      self.curIdx = 0
    else:
      self.curIdx += 1
    self.setImage(self.images[self.curIdx])


  def previous(self):
    if self.curIdx == 0:
      self.curIdx = len(self.images) - 1
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
    self.connect(self.loadedImage, SIGNAL("available(bool)"), self.enableActions)
    self.connect(self.previousButton, SIGNAL("triggered()"), self.previous)
    self.connect(self.nextButton, SIGNAL("triggered()"), self.next)
    self.connect(self.rotlButton, SIGNAL("triggered()"), self.loadedImage.rotateLeft)
    self.connect(self.rotrButton, SIGNAL("triggered()"), self.loadedImage.rotateRight)
    self.connect(self.enlargeButton, SIGNAL("triggered()"), self.loadedImage.enlarge)
    self.connect(self.shrinkButton, SIGNAL("triggered()"), self.loadedImage.shrink)
    self.connect(self.fitButton, SIGNAL("triggered()"), self.loadedImage.fit)
    self.connect(self.normalButton, SIGNAL("triggered()"), self.loadedImage.normal)


  def enableActions(self, cond):
    self.rotlButton.setEnabled(cond)
    self.rotrButton.setEnabled(cond)
    self.enlargeButton.setEnabled(cond)
    self.shrinkButton.setEnabled(cond)
    self.fitButton.setEnabled(cond)
    self.normalButton.setEnabled(cond)


  def setImage(self, node):
    self.imagelabel.setText(str(node.absolute()) + " (" + str(self.curIdx + 1) + " / " + str(len(self.images)) + ")")
    self.loadedImage.load(node)
    self.metadata.process(node)


  def g_display(self):
    QWidget.__init__(self, None)
    self.factor = 1
    self.box = QHBoxLayout()
    self.setLayout(self.box)

    self.imagebox = QVBoxLayout()
    self.scrollArea = QScrollArea()
    self.loadedImage = LoadedImage(self.scrollArea)
    self.scrollArea.setWidget(self.loadedImage)
    self.scrollArea.setAlignment(Qt.AlignCenter)
    self.createActions()
    self.imagelabel = QLabel()
    self.imagebox.addWidget(self.actions)
    self.imagebox.addWidget(self.scrollArea)
    self.imagebox.setAlignment(self.actions, Qt.AlignCenter)
    self.imagebox.addWidget(self.imagelabel)
    self.imagebox.setAlignment(self.imagelabel, Qt.AlignCenter)

    self.databox = QVBoxLayout()
    self.metadata = Metadata()
    self.databox.addWidget(self.metadata)

    if len(self.images) < 2:
      self.nextButton.setEnabled(False)
      self.previousButton.setEnabled(False)

    self.box.addLayout(self.imagebox)
    self.box.addLayout(self.databox)

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
    Module.__init__(self, "pictures", ImageView)
    self.conf.addArgument({"name": "file",
                           "description": "Picture file to display",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    #self.conf.add_const("mime-type", "JPEG")
    #self.conf.add_const("mime-type", "GIF")
    #self.conf.add_const("mime-type", "PNG")
    #self.conf.add_const("mime-type", "PC bitmap")
    self.tags = "Viewers"
