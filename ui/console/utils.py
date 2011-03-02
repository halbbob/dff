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

import re
import os
from api.types.libtypes import typeId

class VariantTreePrinter():
    def __init__(self):
        pass

    def fillMap(self, spacer, vmap, res=""):
        for key in vmap.iterkeys():
            vval = vmap[key]
            res += "\n" + ("\t" * spacer) + str(key)
            expand = True
            if vval.type() == typeId.Map:
                vvmap = vval.value()
                res += self.fillMap(spacer+1, vvmap)
            elif vval.type() == typeId.List:
                vlist = vval.value()
                size = len(vlist)
                if size > 30:
                    expand = False
                res += ": total items (" + str(size) + ")"
                res += self.fillList(spacer+1, vlist)
            elif vval.type() == typeId.VTime:
                vtime = vval.value()
                res += ": " + str(vtime.get_time())
            elif vval.type() in [typeId.Char, typeId.Int16, typeId.UInt16, typeId.Int32, typeId.UInt32, typeId.Int64, typeId.UInt64]:
                
                res += ": " + str(vval.toString() + " - " + vval.toHexString())
            elif vval.type() == typeId.Node:
                res += ": " + str(vval.value().absolute())
            elif vval.type() in [typeId.Path, typeId.String]:
                res += ": " + str(vval.toString())
            #if expand:
            #    self.expandItem(item)
        return res


    def fillList(self, spacer, vlist, res=""):
        for vval in vlist:
            #print "vlist[item] -->", vval.typeName()
            if vval.type() == typeId.Map:
                vmap = vval.value()
                res += self.fillMap(spacer, vmap)
            elif vval.type() == typeId.List:
                vvlist = vval.value()
                res += self.fillList(spacer, vvlist)
            elif vval.type == typeId.VTime:
                vtime = vval.value()
                res += str(vtime.get_time())
            elif vval.type() in [typeId.Char, typeId.Int16, typeId.UInt16, typeId.Int32, typeId.UInt32, typeId.Int64, typeId.UInt64]:
                
                res += str(vval.toString() + " - " + vval.toHexString())
            elif vval.type() == typeId.Node:
                res += str(vval.value().absolute())
            elif vval.type() in [typeId.Path, typeId.String]:
                res += str(vval.toString())
            #if expand:
            #    self.expandItem(item)
        return res
