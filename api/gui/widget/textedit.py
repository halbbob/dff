from PyQt4.QtGui import QTextEdit
from PyQt4.QtCore import SIGNAL

class TextEdit(QTextEdit):
  def __init__(self, proc):
      QTextEdit.__init__(self)
      self.setReadOnly(1)
      self.icon = 0
      self.name = proc.name()
      self.type = "autogen"
      self.proc = proc 
      proc.widget = self
      self.connect(self, SIGNAL("puttext"), self.puttext)

  def puttext(self, text):
      self.append(text)		


