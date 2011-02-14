# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2011 ArxSys
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
#  Solal Jacob <sja@digital-forensic.org>
# 

from PyQt4.QtGui import QWidget, QAction, QStyle, QToolBar, QLabel, QPalette, QPixmap, QLCDNumber, QSizePolicy, QHBoxLayout, QVBoxLayout, QMessageBox
from PyQt4.QtCore import SIGNAL, SLOT, QTime, Qt
from PyQt4.phonon import Phonon 

from api.module.script import Script 
from api.module.module import Module
from api.vfs.iodevice import IODevice
from api.types.libtypes import Argument, typeId
from api.vfs import *

class PLAYER(QWidget, Script):
  def __init__(self):
     Script.__init__(self, "player")
     self.vfs = vfs.vfs() 

  def start(self, args):
    try:
      self.node = args["file"].value()
    except:
      pass

  def updateWidget(self):
    pass

  def g_display(self):
     QWidget.__init__(self)

     self.media = Phonon.MediaObject(self)
     self.video = Phonon.VideoWidget(self)
     self.audio = Phonon.AudioOutput(Phonon.MusicCategory, self)

     self.media.setTickInterval(1000)
     self.media.tick.connect(self.tick)
     self.media.stateChanged.connect(self.stateChanged)
     #self.media.currentSourceChanged.connect(self.sourceChanged)
#     self.media.aboutToFinish.connect(self.aboutToFinish)

     Phonon.createPath(self.media, self.video)
     Phonon.createPath(self.media, self.audio)
    
     self.setupActions()
     self.setupUi()
     self.timeLcd.display("00:00") 
 
     self.play(self.node)

  def play(self, node):
     wasPlaying = (self.media.state() == Phonon.PlayingState)
     self.media.stop()
     self.media.clearQueue()
     self.src = IODevice(node)
     source = Phonon.MediaSource(self.src)
     if source.type() != -1:
	self.media.setCurrentSource(source)
        if  wasPlaying:
          self.media.play()
        else :
	  self.media.stop()
     else:
	print "error can find file"

  def tick(self, time):
        displayTime = QTime(0, (time / 60000) % 60, (time / 1000) % 60)
        self.timeLcd.display(displayTime.toString('mm:ss'))

  def stateChanged(self, newState, oldState):
        if newState == Phonon.ErrorState:
            if self.media.errorType() == Phonon.FatalError:
                QMessageBox.warning(self, "Fatal Error",
                        self.media.errorString())
            else:
                QMessageBox.warning(self, "Error",
                        self.media.errorString())

        elif newState == Phonon.PlayingState:
            self.playAction.setEnabled(False)
            self.pauseAction.setEnabled(True)
            self.stopAction.setEnabled(True)

        elif newState == Phonon.StoppedState:
            self.stopAction.setEnabled(False)
            self.playAction.setEnabled(True)
            self.pauseAction.setEnabled(False)
            self.timeLcd.display("00:00")

        elif newState == Phonon.PausedState:
            self.pauseAction.setEnabled(False)
            self.stopAction.setEnabled(True)
            self.playAction.setEnabled(True)


  def setupActions(self):
        self.playAction = QAction(
                self.style().standardIcon(QStyle.SP_MediaPlay), "Play",
                self, shortcut="Ctrl+P", enabled=False,
                triggered=self.media.play)

        self.pauseAction = QAction(
                self.style().standardIcon(QStyle.SP_MediaPause),
                "Pause", self, shortcut="Ctrl+A", enabled=False,
                triggered=self.media.pause)

        self.stopAction = QAction(
                self.style().standardIcon(QStyle.SP_MediaStop), "Stop",
                self, shortcut="Ctrl+S", enabled=False,
                triggered=self.media.stop)

        self.nextAction = QAction(
                self.style().standardIcon(QStyle.SP_MediaSkipForward),
                "Next", self, shortcut="Ctrl+N")

        self.previousAction = QAction(
                self.style().standardIcon(QStyle.SP_MediaSkipBackward),
                "Previous", self, shortcut="Ctrl+R")

  def setupUi(self):
        bar = QToolBar()

        bar.addAction(self.playAction)
        bar.addAction(self.pauseAction)
        bar.addAction(self.stopAction)

        self.seekSlider = Phonon.SeekSlider(self)
        self.seekSlider.setMediaObject(self.media)

        self.volumeSlider = Phonon.VolumeSlider(self)
        self.volumeSlider.setAudioOutput(self.audio)
        self.volumeSlider.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)

        volumeLabel = QLabel()
        volumeLabel.setPixmap(QPixmap('images/volume.png'))

        palette = QPalette()
        palette.setBrush(QPalette.Light, Qt.darkGray)

        self.timeLcd = QLCDNumber()
        self.timeLcd.setPalette(palette)

        headers = ("Title", "Artist", "Album", "Year")

        seekerLayout = QHBoxLayout()
        seekerLayout.addWidget(self.seekSlider)
        seekerLayout.addWidget(self.timeLcd)

        playbackLayout = QHBoxLayout()
        playbackLayout.addWidget(bar)
        playbackLayout.addStretch()
        playbackLayout.addWidget(volumeLabel)
        playbackLayout.addWidget(self.volumeSlider)

        mainLayout = QVBoxLayout()
        mainLayout.addWidget(self.video)
        mainLayout.addLayout(seekerLayout)
        mainLayout.addLayout(playbackLayout)

        self.setLayout(mainLayout)


class player(Module):
  def __init__(self):
   """Video and Audio player"""
   Module.__init__(self, "player", PLAYER)
   self.conf.addArgument({"name": "file",
                          "description": "multimedia file to play",
                          "input": Argument.Required|Argument.Single|typeId.Node})
   self.tags = "Viewers"
   #for mimeType in Phonon.BackendCapabilities.availableMimeTypes():
     #self.conf.add_const("mime-type", str(mimeType))
   #self.conf.add_const("mime-type", "video")
