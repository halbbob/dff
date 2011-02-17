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

from PyQt4.QtCore import Qt, QString, QEvent
from PyQt4.QtGui import QTreeWidget, QTreeWidgetItem
from api.types.libtypes import typeId
from ui.gui.resources.ui_varianttreewidget import Ui_VariantTreeWidget

class VariantTreeWidget(QTreeWidget, Ui_VariantTreeWidget):
    def __init__(self, parent=None):
        QTreeWidget.__init__(self, parent)
        self.setupUi(self)

    def fillMap(self, parent, vmap):
        for key in vmap.iterkeys():
            item = QTreeWidgetItem(parent)
            item.setText(0, str(key))
            vval = vmap[key]
            #print "vmap[" + str(key) + "] -->", vval.typeName()
            expand = True
            if vval.type() == typeId.Map:
                vvmap = vval.value()
                self.fillMap(item, vvmap)
            elif vval.type() == typeId.List:
                vlist = vval.value()
                size = len(vlist)
                if size > 30:
                    expand = False
                item.setText(1, "total items (" + str(size) + ")")
                self.fillList(item, vlist)
            elif vval.type() == typeId.VTime:
                vtime = vval.value()
                item.setText(1, str(vtime.get_time()))
            elif vval.type() in [typeId.Char, typeId.Int16, typeId.UInt16, typeId.Int32, typeId.UInt32, typeId.Int64, typeId.UInt64]:
                item.setText(1, vval.toString() + " - " + vval.toHexString())
            else:
                val = vval.value()
                item.setText(1, str(val))
            if expand:
                self.expandItem(item)


    def fillList(self, parent, vlist):
        for vval in vlist:
            #print "vlist[item] -->", vval.typeName()
            if vval.type() == typeId.Map:
                vmap = vval.value()
                self.fillMap(parent, vmap)
            elif vval.type() == typeId.List:
                vvlist = vval.value()
                self.fillList(parent, vvlist)
            elif vval.type == typeId.VTime:
                vtime = vval.value()
                item = QTreeWidgetItem(parent)
                item.setText(1, str(vtime.get_time()))
            elif vval.type() in [typeId.Char, typeId.Int16, typeId.UInt16, typeId.Int32, typeId.UInt32, typeId.Int64, typeId.UInt64]:
                item = QTreeWidgetItem(parent)
                item.setText(1, vval.toString() + " - " + vval.toHexString())
            else:
                val = vval.value()
                item = QTreeWidgetItem(parent)
                item.setText(1, str(val))

    def changeEvent(self, event):
        """ Search for a language change event
        
        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
        else:
            QTreeWidget.changeEvent(self, event)
