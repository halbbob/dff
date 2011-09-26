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

from PyQt4.QtCore import Qt, QString, QEvent, SIGNAL
from PyQt4.QtGui import QTreeWidget, QTreeWidgetItem, QMessageBox
from api.types.libtypes import typeId
from ui.gui.resources.ui_varianttreewidget import Ui_VariantTreeWidget

class VariantTreeWidget(QTreeWidget, Ui_VariantTreeWidget):
    def __init__(self, parent=None):
        QTreeWidget.__init__(self, parent)
        self.setupUi(self)

        self.connect(self, SIGNAL("itemDoubleClicked(QTreeWidgetItem*, int)"), self.displayItem)

    def setItemText(self, item, vval):
        if vval == None:
	    item.setText(1, str("None")) 
        elif vval.type() == typeId.VTime:
            vtime = vval.value()
	    if vtime:
              item.setText(1, str(vtime.get_time()))
        elif vval.type() in [typeId.Int16, typeId.UInt16, typeId.Int32, typeId.UInt32, typeId.Int64, typeId.UInt64]:
            item.setText(1, vval.toString() + " - " + vval.toHexString())
        elif vval.type() in [typeId.Char, typeId.String, typeId.CArray]:
            val = vval.toString()
            item.setText(1, QString.fromUtf8(val))
        elif vval.type() == typeId.Node:
            item.setText(1, QString.fromUtf8(vval.value().absolute()))
        elif vval.type() == typeId.Path:
            item.setText(1, QString.fromUtf8(vval.value().path))
        else:
            item.setText(1, str(vval.value()))


    def fillMap(self, parent, vmap):
        for key in vmap.iterkeys():
            item = QTreeWidgetItem(parent)
#            item.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
            item.setText(0, QString.fromUtf8(key))
            vval = vmap[key]
            expand = True
	    if vval == None:
	      self.setItemText(item, vval)	
            elif vval.type() == typeId.Map:
                vvmap = vval.value()
                self.fillMap(item, vvmap)
            elif vval.type() == typeId.List:
                vlist = vval.value()
                size = len(vlist)
                if size > 30:
                    expand = False
                item.setText(1, "total items (" + str(size) + ")")
                self.fillList(item, vlist)
            else:
                self.setItemText(item, vval)
            if expand:
                self.expandItem(item)


    def fillList(self, parent, vlist):
        for vval in vlist:
            if vval.type() == typeId.Map:
                vmap = vval.value()
                self.fillMap(parent, vmap)
            elif vval.type() == typeId.List:
                vvlist = vval.value()
                self.fillList(parent, vvlist)
            else:
                item = QTreeWidgetItem(parent)
                self.setItemText(item, vval)

    def displayItem(self, item, col):
        message = QString()
        it = 0
        for it in xrange(0,item.columnCount()):
            message.append(item.text(it))
            if it != item.columnCount() - 1:
                message.append(":\n")
        msg = QMessageBox(self)
        msg.setText(message)
        msg.setIcon(QMessageBox.Information)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def changeEvent(self, event):
        """ Search for a language change event
        
        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
        else:
            QTreeWidget.changeEvent(self, event)
