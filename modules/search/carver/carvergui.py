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
#  Frederic B. <fba@digital-forensic.org>

from api.module.module import Module
from api.module.script import Script
from api.events.libevents import EventHandler, event
from api.types.libtypes import typeId, Argument, Parameter, VList, VMap, Variant
from api.taskmanager.taskmanager import TaskManager

from PyQt4.QtGui import QWidget, QVBoxLayout, QGridLayout, QLabel, QProgressBar, QHBoxLayout, QCheckBox, QPushButton, QTabWidget
from PyQt4.Qt import SIGNAL

from typeSelection import filetypes, wildcard

import string

import time

from predef import predefPattern
from userdef import userPattern

from modules.search.carver.utils import QFFSpinBox


class carvingProcess(QWidget, EventHandler):
    def __init__(self):
        QWidget.__init__(self)
        EventHandler.__init__(self)
        self.layout = QVBoxLayout()
        self.grid = QGridLayout()
        self.info = QVBoxLayout()
        self.layout.addLayout(self.grid)
        self.layout.addLayout(self.info)
        self.setLayout(self.layout)
        self.currentLabel = QLabel("Overall progress :")
        self.elapsedLabel = QLabel("elapsed time:    00d00h00m00s")
        self.estimatedLabel = QLabel("estimated time: 00d00h00m00s")
        self.totalLabel = QLabel("total headers found: 0")
        self.currentProgress = QProgressBar()
        self.grid.addWidget(self.currentLabel, 0, 0)
        self.grid.addWidget(self.currentProgress, 0, 1)
        self.info.addWidget(self.elapsedLabel)
        self.info.addWidget(self.estimatedLabel)
        self.info.addWidget(self.totalLabel)
        self.factor = 1
        self.parsetime = 0
        self.time = time.time()
        self.starttime = time.time()

    def strtime(self, day, hour, min, sec):
        day = str(day)
        hour = str(hour)
        min = str(min)
        sec = str(sec)
        res = "0" * (2-len(day)) + day + "d" + "0" * (2-len(hour)) + hour + "h" + "0" * (2-len(min)) + min + "m" + "0" * (2-len(sec)) + sec + "s"
        return res

    def timesec2str(self, timesec):
        day = hour = min = sec = 0
        if timesec > 3600 * 24:
            day = timesec / (3600 * 24)
            timesec = timesec % (3600 * 24)
        if timesec > 3600:
            hour = timesec / 3600
            timesec = timesec % 3600
        if timesec > 60:
            min = timesec / 60
            timesec = timesec % 60
        sec = timesec
        res = self.strtime(int(day), int(hour), int(min), int(sec))
        return res


    def Event(self, e):
        if e.type == event.SEEK:
            self.emit(SIGNAL("update"), e)
        elif e.type == event.OTHER:
            if e.value.type() == typeId.String and e.value == "terminated":
                self.end("")
            else:
                self.emit(SIGNAL("update"), e)


    def update(self, e):
        if e.type == event.SEEK:
            ref = time.time() - self.time
            self.time = time.time()
            if not str(ref).startswith("0.0"):
                ref *= self.parsetime
                res = self.timesec2str(ref)
                self.estimatedLabel.setText("estimated time: " + res)
            res = self.timesec2str(time.time() - self.starttime)
            self.elapsedLabel.setText("elapsed time:    " + res)
            i = int(e.value.value() / self.factor)
            if i > 2147483647:
                i = 2147483647
            self.emit(SIGNAL("valueChanged(int)"), i)
            info = self.currentProgress.text() + " - " + self.totalLabel.text()
            self.emit(SIGNAL("stateInfo(QString)"), info)
        else:
            self.totalLabel.setText("total headers found: " + str(e.value))
            


    def doJob(self, filesize, factor, start):
        self.factor = factor
        self.parsetime = filesize / (10*1204*1024)
        self.elapsedLabel.setText("elapsed time:    00d00h00m00s")
        self.estimatedLabel.setText("estimated time: 00d00h00m00s")
        self.totalLabel.setText("total headers found: 0")
        maxrange = int(filesize / self.factor)
        if maxrange > 2147483647:
            maxrange = 2147483647
        self.currentProgress.setRange(0, maxrange)
        self.currentProgress.setValue(0)
        self.connect(self, SIGNAL("valueChanged(int)"), self.currentProgress.setValue)
        self.time = time.time()
        self.starttime = time.time()
        self.connect(self, SIGNAL("update"), self.update)

        
    def end(self, res):
        self.hide()
        self.emit(SIGNAL("end(QString)"), res)


    def killJob(self):
        e = event()
        e.thisown = False
        val = Variant(1)
        val.thisown = False
        e.value = val
        e.type = event.SEEK
        self.notify(e)


class CarverGui(QWidget, Script):
    def __init__(self):
        Script.__init__(self, "carver-gui")
        self.tm = TaskManager()


    def start(self, args):
        self.args = args
        self.node = args["file"].value()
        self.name += " <" + self.node.name() + ">"
        self.filesize = self.node.size()


    def status(self):
        return 0


    def g_display(self):
        QWidget.__init__(self)
        self.draw()
        

    def updateWidget(self):
        pass


    def startOffset(self):
        self.offsetLayout = QHBoxLayout()
        self.offsetSpinBox = QFFSpinBox(self)
        self.offsetSpinBox.setMinimum(0)
        self.offsetSpinBox.setMaximum(self.filesize)
        self.offsetLabel = QLabel("start offset:")
        self.offsetLayout.addWidget(self.offsetLabel)
        self.offsetLayout.addWidget(self.offsetSpinBox)


    def setStateInfo(self, sinfo):
        self.stateinfo = str(sinfo)


    def draw(self):
        #define layout
        self.vbox = QVBoxLayout()
        self.setLayout(self.vbox)
        self.tabwidgets = QTabWidget()

        #define all area
        self.user = userPattern()
        self.pp = predefPattern()
        self.tabwidgets.addTab(self.pp, "Predefined")
        self.tabwidgets.addTab(self.user, "User defined")
        self.startButton = QPushButton("Start")
        self.stopButton = QPushButton("Stop")
        self.alignedCheck = QCheckBox("match only at the beginning of sector")
        self.startOffset()
        self.carvingProcess = carvingProcess()
        
        #add widget and hide progress bars
        self.vbox.addWidget(self.tabwidgets)
        #self.vbox.addWidget(self.user)
        self.vbox.addLayout(self.offsetLayout)
        self.vbox.addWidget(self.alignedCheck)
        self.vbox.addWidget(self.startButton)
        self.vbox.addWidget(self.stopButton)
        self.vbox.addWidget(self.carvingProcess)
        self.carvingProcess.hide()
        self.stopButton.setEnabled(False)

        #define connectors
        self.connect(self.stopButton, SIGNAL("clicked()"), self.stopCarving)
        self.connect(self.startButton, SIGNAL("clicked()"), self.startCarving)
        self.connect(self.carvingProcess, SIGNAL("end(QString)"), self.carvingEnded)


    def carvingEnded(self, res):
        #results = str(res).split("\n")
        #print results
        #for item in results:
        #    begidx = item.find(":")
        #    self.res.add_const(str(item[:begidx]), str(item[begidx+1:] + "\n"))
        self.startButton.setEnabled(True)
        self.stopButton.setEnabled(False)


    def stopCarving(self):
        self.carvingProcess.killJob()
        self.stopButton.setDown(True)


    def createContext(self, selected):
        patterns = VList()
        patterns.thisown = False
        for key, items in selected.iteritems():
            for item in items:
                pattern = VMap()
                pattern.thisown = False
                descr = filetypes[key][item]
                filetype = Variant(item, typeId.String)
                filetype.thisown = False
                for p in descr:
                    pattern["filetype"] = filetype
                    header = VMap()
                    header.thisown = False
                    val = Variant(p[0], typeId.String)
                    val.thisown = False
                    header["needle"] = val
                    val = Variant(len(p[0]), typeId.UInt32)
                    val.thisown = False
                    header["size"] = val
                    footer = VMap()
                    footer.thisown = False
                    val = Variant(p[1], typeId.String)
                    val.thisown = False
                    footer["needle"] = val
                    val = Variant(len(p[1]), typeId.UInt32)
                    val.thisown = False
                    footer["size"] = val
                    if p[0].find(wildcard) != -1:
                        val = Variant(wildcard, typeId.Char)
                        val.thisown = False
                        header["wildcard"] = val
                    else:
                        val = Variant("", typeId.Char)
                        val.thisown = False
                        header["wildcard"] = val
                    if p[1].find(wildcard) != -1:
                        val = Variant(wildcard, typeId.Char)
                        val.thisown = False
                        footer["wildcard"] = val
                    else:
                        val = Variant("", typeId.Char)
                        val.thisown = False
                        footer["wildcard"] = val
                    vheader = Variant(header)
                    vheader.thisown = False
                    pattern["header"] = vheader
                    vfooter = Variant(footer)
                    vfooter.thisown = False
                    pattern["footer"] = vfooter
                    pattern["window"] = Variant(int(p[2]), typeId.UInt32)
                    if self.alignedCheck.isChecked():
                        val = Variant(True, typeId.Bool)
                        val.thisown = False
                        pattern["aligned"] = val
                    else:
                        val = Variant(False, typeId.Bool)
                        val.thisown = False
                        pattern["aligned"] = val
                    patterns.append(pattern)
        vpatterns = Variant(patterns)
        vpatterns.thisown = False
        return vpatterns
        

    def startCarving(self):
        self.startButton.setEnabled(False)
        self.stopButton.setEnabled(True)
        self.stopButton.setDown(False)
        selected = self.pp.getChecked()
        patterns = self.createContext(selected)
        args = VMap()
        args.thisown = False
        args["patterns"] = patterns
        args["file"] = self.args["file"]
        startoff = Variant(self.offsetSpinBox.value(), typeId.UInt64)
        startoff.thisown = False
        args["start-offset"] = startoff
        factor = round(float(self.filesize) / 2147483647)
        if factor == 0:
            factor = 1
        proc = self.tm.add("carver", args, ["gui", "thread"])
        if proc:
            self.carvingProcess.doJob(self.filesize, factor, self.offsetSpinBox.value())
            self.carvingProcess.show()
            self.carvingProcess.connection(proc.inst)
            proc.inst.connection(self.carvingProcess)
            self.connect(self.carvingProcess, SIGNAL("stateInfo(QString)"), self.setStateInfo)


class carvergui(Module):
  """Search for header and footer of a selected mime-type in a node and create the corresponding file.
     You can use this modules for finding deleted data or data in slack space or in an unknown file system."""
  def __init__(self):
    Module.__init__(self, 'carvergui', CarverGui)
    self.conf.addArgument({"name": "file",
                           "input": typeId.Node|Argument.Single|Argument.Required,
                           "description": "Node to search data in"})
    self.tags = "Search"
