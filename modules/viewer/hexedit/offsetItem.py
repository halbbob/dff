import binascii
import struct
import string
import time


from PyQt4.QtCore import QString, Qt
from PyQt4.QtGui import QWidget, QFont, QColor, QTextCursor, QGraphicsTextItem

class offsetItem(QGraphicsTextItem):
    def __init__(self, whex):
        QGraphicsTextItem.__init__(self)
        self.initValues(whex)
#        self.initShape()
        self.initPosition()
        self.initFont()

    def initPosition(self):
        self.setPos(0, 25)

    def initValues(self, whex):
        self.whex = whex
        self.heditor = self.whex.heditor
        #Buffer
        self.buffer = []
        self.bufferLines = 0 
        #Line
        self.currentLine = 0
        #Offset
        self.startOffset = 0
        self.fontPixel = 14

    def initFont(self):
        self.setDefaultTextColor(QColor(Qt.red))

        self.font = QFont("Gothic")
        self.font.setFixedPitch(1)
        self.font.setBold(False)
        self.font.setPixelSize(self.fontPixel)
        self.setFont(self.font)

    #Print Operations
    def printFullOffset(self, start, len):
        count = 0
        fullBuff = QString()

        while count <= len:
            if self.heditor.decimalview:
                fullBuff.append("%.10d" % start)
            else:
                fullBuff.append("%.10X" % start)
            fullBuff.append("\n")
            start += 16
            count += 1

        #Clear and set
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.Start)
        cursor.movePosition(QTextCursor.End, QTextCursor.KeepAnchor)
        self.setPlainText(fullBuff)
        cursor.movePosition(QTextCursor.Start)
