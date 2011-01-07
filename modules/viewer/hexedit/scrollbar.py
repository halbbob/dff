# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009 ArxSys
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
#  Jeremy Mounier <jmo@digital-forensic.org>
#

#import sys
#Is digit
#import re
import os


from PyQt4.QtCore import Qt, SIGNAL
from PyQt4.QtGui import QScrollBar, QAbstractSlider

class hexScrollBar(QScrollBar):
    def __init__(self, whex):
        QScrollBar.__init__(self)
        self.init(whex)
        self.initCallBacks()
#        self.setValues()

    def init(self, whex):
        self.whex = whex
        self.heditor = self.whex.heditor
        self.filesize = self.heditor.filesize
        self.min = 0
        self.single = 1
        #Initialized in Whex with LFMOD
        self.page = self.heditor.pageSize
        self.max = 0

        #Long File Mode
#        self.lfmod = False

        ###### LFMOD ######
        ###################
#        self.maxint = 2147483647
#        self.lines = self.filesize / self.heditor.bytesPerLine
#        self.restlines = self.filesize % 16
#        if self.isInt(self.lines):
#            self.max = self.lines - 1
#            self.page = self.heditor.pageSize / 16
#        else:
#            self.lfmod = True
#            self.max = self.maxint - 1
#            self.page = self.heditor.pageSize
        ####################
        ####################

    def initCallBacks(self):
        self.connect(self, SIGNAL("sliderMoved(int)"), self.moved) 
        self.connect(self, SIGNAL("actionTriggered(int)"), self.triggered) 

    def setValues(self):
        self.setMinimum(self.min)
        self.setMaximum(self.max)
        self.setSingleStep(self.single)
        self.setPageStep(self.page)
        self.setRange(self.min, self.max)

#    def isLFMOD(self):
#        return self.lfmod

#    def isInt(self, val):
#        try:
#            res = int(val)
#            if res <  2147483647:
#                return True
#            else:
#                return False
#        except ValueError, TypeError:
#            return False
#        else:
#            return False

    # LFMOD #
#    def valueToOffset(self, value):
#        return ((self.filesize * value) / self.maxint)

#    def offsetToValue(self, offset):
#        if self.isLFMOD():
#            return ((self.maxint * offset) / self.filesize)
#        else:
#            return (offset / self.heditor.bytesPerLine)

########################################
#          Navigation Operations       #
########################################

    def triggered(self, action):
        if action == QAbstractSlider.SliderSingleStepAdd:
            self.whex.view.move(self.singleStep(), 1)
        elif action == QAbstractSlider.SliderSingleStepSub:
            self.whex.view.move(self.singleStep(), 0)
        elif action == QAbstractSlider.SliderPageStepSub:
            self.whex.view.move(self.pageStep(), 0)
        elif action == QAbstractSlider.SliderPageStepAdd:
            self.whex.view.move(self.pageStep(), 1)


#    def oldtriggered(self, action):
#        offset = self.heditor.currentOffset
        #######################
        #        LINES        #
        #######################
        #LINE DOWN
#        if action == QAbstractSlider.SliderSingleStepAdd:
#            if offset + 16 <= (self.filesize - 5 * 16):
#                self.heditor.readOffset(offset + 16)
                #Update value
#                if self.isLFMOD():
#                    self.setValue(self.offsetToValue(offset + 16))
#                else:
#                    self.setValue(self.value() + 1)
        #LINE UP
#        elif action == QAbstractSlider.SliderSingleStepSub:
#            if offset - 16 >= 0:
#                self.heditor.readOffset(offset - 16)
#                #Update value
#                if self.isLFMOD():
#                    self.setValue(self.offsetToValue(offset - 16))
#                else:
#                    self.setValue(self.value() - 1)
        #######################
        #        PAGES        #
        #######################
        #PAGE UP
#        elif action == QAbstractSlider.SliderPageStepSub:
#            if offset - (self.page * 16) >= 0:
#                self.heditor.readOffset(offset - (self.page * 16))
#                #Update value
#                if self.isLFMOD():
#                    self.setValue(self.offsetToValue(offset - (self.page * 16)))
#                else:
#                    self.setValue(self.value() - self.page)
        #PAGE DOWN
#        elif action == QAbstractSlider.SliderPageStepAdd:
#            if offset + (self.page * 16) <= self.filesize - (5* 16):
#                self.heditor.readOffset(offset + (self.page * 16))
#                #Update value
#                if self.isLFMOD():
#                    self.setValue(self.offsetToValue(offset + (self.page * 16)))
#                else:
#                    self.setValue(self.value() + self.page)

    def moved(self, value):
        if self.whex.isLFMOD():
            if value <= self.max:
                offset = (self.filesize * value) / self.whex.maxint
                self.heditor.readOffset(offset)
        else:
            if value <= self.max:
                if value == self.max:
                    offset = self.filesize - (5 * self.heditor.bytesPerLine)
                else:
                    offset = value * self.heditor.bytesPerLine
                self.heditor.readOffset(offset)

class pageScrollBar(QScrollBar):
    def __init__(self, wpage):
        QScrollBar.__init__(self)
        self.wpage = wpage
        self.pageview = wpage.view
        self.heditor = wpage.heditor
        self.initCallBacks()
        self.initValues()
        self.setValues()
        #LFMOD

    def initCallBacks(self):
        self.connect(self, SIGNAL("sliderMoved(int)"), self.moved) 
        self.connect(self, SIGNAL("actionTriggered(int)"), self.triggered)

    def initValues(self):
        self.min = 0
        self.max = self.pageview.lines - 5
        self.page = self.pageview.lines / self.heditor.pagesPerBlock

    def refreshValues(self, len, pagesize):
        self.pageview.lines = self.heditor.filesize / (len * pagesize)
        self.min = 0
        self.max = self.pageview.lines - 5
#        print "max line refresh: ", self.pageview.lines
        self.page = self.pageview.lines / len
        self.setValues()

    def setValues(self):
        self.setMinimum(0)
        self.setMaximum(self.max)
        self.setSingleStep(1)
        self.setPageStep(self.page)
        self.setRange(0, self.max)

    def valueToOffset(self, value):
        return (value * (self.heditor.pagesPerBlock * self.heditor.pageSize))

    def offsetToValue(self, offset):
        return (offset / (self.heditor.pagesPerBlock * self.heditor.pageSize))

    def triggered(self, action):
        offset = self.heditor.startBlockOffset
        #######################
        #        LINE         #
        #######################
        #LINE DOWN
        addOffset = self.heditor.pagesPerBlock * self.heditor.pageSize
        if action == QAbstractSlider.SliderSingleStepAdd:
            if offset + addOffset <= (self.pageview.filesize - 5 * addOffset):
                self.pageview.refreshOffsetItems(offset + addOffset)
                self.pageview.refreshPageItems(offset + addOffset)
        elif action == QAbstractSlider.SliderSingleStepSub:
            if offset - addOffset >= 0:
                self.pageview.refreshOffsetItems(offset - addOffset)
                self.pageview.refreshPageItems(offset - addOffset)

    def moved(self, value):
        if value < self.max:
            offset = self.valueToOffset(value)
            if offset < self.heditor.filesize and offset >= 0:
                self.pageview.refreshOffsetItems(offset)
                self.pageview.refreshPageItems(offset)
        else:
            self.pageview.refreshOffsetItems(self.pageview.filesize)
            self.pageview.refreshPageItems(self.pageview.filesize)

####################################
#            PIXEL VIEW            #
####################################

class byteScrollBar(QScrollBar):
    def __init__(self, wpixel):
        QScrollBar.__init__(self)
        self.initCallBacks()
        self.initValues(wpixel)
        self.setValues()

    def initCallBacks(self):
        self.connect(self, SIGNAL("sliderMoved(int)"), self.moved) 
        self.connect(self, SIGNAL("actionTriggered(int)"), self.triggered)     

    def initValues(self, wpixel):
        self.wpixel = wpixel
        self.bview = wpixel.view
        self.min = 0
        self.max = self.bview.hmax
        self.page = self.bview.w * 16

    def refreshValues(self):
        #mode: rgb | index | mono
        if self.bview.format > 1:
            self.min = 0
            self.max = self.bview.filesize / (self.bview.w * 4)
            self.page = self.bview.w * 16
        else:
            self.min = 0
            self.max = self.bview.filesize / self.bview.w
            self.page = self.bview.w * 16
        self.setValues()

    def setValues(self):
        self.setMinimum(0)
        self.setMaximum(self.max)
        self.setSingleStep(1)
        self.setPageStep(self.page)
        self.setRange(0, self.max)

    def triggered(self, action):
        pass

    def moved(self, value):
        if value != self.max:
            if self.bview.format < 2:
                self.bview.read_image(value * self.bview.w)
            else:
                self.bview.read_image(value * (self.bview.w * 4))
        else:
            if self.bview.format < 2:
                self.bview.read_image((value - 32) * self.bview.w)
            else:
                self.bview.read_image((value - 32) * (self.bview.w * 4))
#        self.setValue(value)
