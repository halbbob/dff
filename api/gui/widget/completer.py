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

#from PyQt4.QtCore import 
from PyQt4.QtGui import QLineEdit, QCompleter, QWidget
from PyQt4.QtCore import Qt, QObject, QString, SIGNAL


from api.gui.model.vfsitemmodel import CompleterModel
from api.vfs.vfs import vfs

class Completer(QCompleter):
    def __init__(self):
        QCompleter.__init__(self)
        self.vfs = vfs()
        self.__model = CompleterModel()
        self.currentNode = self.vfs.getnode("/")
        self.currentPath = self.currentNode
        self.setCompletionPrefix(QString.fromUtf8(self.currentNode.absolute()))
        self.__model.setRootPath(self.currentNode)
        self.__model.setCurrentPath("/")
        self.setModel(self.__model)
        QObject.connect(self, SIGNAL("activated(const QString &)"), self.updatePath)


    def pathChanged(self, path):
        self.currentPath = self.vfs.getnode(path)


    def updatePath(self, path):
        path = unicode(path)
        self.curpath = path
        if path == "":
            abspath = "/"
        else:
            if path[0] == "/":
                self.__model.setCurrentPath("")
                idx = path.rfind("/")
                abspath = path[:idx]
            else:
                abspath = self.currentPath.absolute()
                self.__model.setCurrentPath(abspath)
                idx = path.rfind("/")
                if idx != -1:
                    abspath += path[:idx]
        self.currentNode = self.vfs.getnode(unicode(abspath).encode('utf-8'))
        self.__model.setRootPath(self.currentNode)
        self.setCompletionPrefix(QString.fromUtf8(self.currentNode.absolute()))


class CompleterWidget(QLineEdit):
    def __init__(self, parent=None):
        QLineEdit.__init__(self)
        self.completer = Completer()
        self.setCompleter(self.completer)
        self.completer.setCompletionMode(QCompleter.PopupCompletion)
        self.completer.setCompletionRole(Qt.DisplayRole)
        self.completer.setCaseSensitivity(Qt.CaseInsensitive)
        QObject.connect(self, SIGNAL("textEdited(const QString &)"), self.completer.updatePath)

    #def keyPressEvent(self, keyev):
        #if keyev.key() == 

    def editFinished(self):
        text = self.text()
        self.completer.updatePath(QString.fromUtf8(text))
        
    def pathChanged(self, path):
        self.setText(QString.fromUtf8(path))
        self.completer.pathChanged(path)
