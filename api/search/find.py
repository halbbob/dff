# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2010 ArxSys
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


#normalized input
# StringFilter.type in [regexp, wildcard, fixed string]
# DateFilter

# testPattern = (a AND b) OR NOT ((c AND a) AND (a AND (b OR c)))

import re
import types
import datetime
# fso --> managedAttributes()
import traceback

from api.vfs.vfs import vfs, VFS
from api.vfs.libvfs import ABSOLUTE_ATTR_NAME, AttributesIndexer
from api.events.libevents import EventHandler
from api.types.libtypes import typeId, VMap
import time, datetime

class BooleanFilter():
    def __init__(self):
        pass

    
    def match(self, node, filter):
        ret = False
        field = filter[0]
        expr = filter[1]
        f = None
        for attr in dir(node):
            if attr.lower().find(field) != -1:
                f = getattr(node, attr)
                break
        if f != None:
            try:
                ret = eval("f() == bool(expr)")
            except:
                ret = False
        return ret


    def priority(self):
        return 0
            

#{"name": "w(DSC*.jpg) and f(pouet) or re()"}
class StringFilter():
    def __init__(self):
        pass


    def __decodeStr(self, strexpr, val):
        lstr = strexpr.split()
        res = []
        for f in lstr:
            if f.startswith("w(") and f[-1] == ")":
                #res.append((f, wildre.match))
                f2 = f[2:-1]
                for c in ["\\", ".", "^", "$", "+", "?", "{", "[", "]", "|", "(", ")"]:
                    f2 = f2.replace(c, "\\"+c)
                f2 = f2.replace("*", ".*")
                f2 += "$"
                res.append((f, "re.search(\""+ f2 + "\"," + "\"" + val + "\")"))
            if f.startswith("f(") and f[:-1] == ")":
                res.append((f, "val==" + f[2:-2]))
            if f.startswith("re(") and f[:-1] == ")":
                regexp = re.compile(f[3:-2])
                res.append(regexp)
        return res


    def match(self, node, filter):
        ret = False
        field = filter[0]
        expr = filter[1]
        val = None
        #print field
        if hasattr(node, field):
            val = getattr(node, field)()
        else:
            attr = node.attributesByName(field, ABSOLUTE_ATTR_NAME)
            #print attr
            if attr != None:
                val = attr.value()
        if val != None:
            expressions = self.__decodeStr(expr, val)
            for i in xrange(len(expressions)):
                expr = expr.replace(expressions[i][0], expressions[i][1])
            try:
                ret = eval(expr)
            except SyntaxError:
                ret = False 
        return ret


    def priority(self):
        return 2


class TimeFilter():
    def __init__(self):
        pass


    def strToDate(self, strexpr):
        res = []
        expr = re.compile("\d{4,4}/{1,1}\d{1,2}/{1,1}\d{1,2}")
        for d in expr.findall(strexpr):
            res.append((d, datetime.datetime(*tuple(map(lambda x: int(x), d.split("/"))))))
        return res


    def match(self, node, filter):
        ret = False
        field = filter[0]
        expr = filter[1]
        val = None
        attr = node.attributesByName(field, ABSOLUTE_ATTR_NAME)
        if attr != None:
            val = attr.value()
            if val != None:
                dates = self.strToDate(expr)
                for i in xrange(len(dates)):
                    expr = expr.replace(dates[i][0], "dates[" + str(i) + "][1]")
                for operator in ["<", ">", "==", "in"]:
                    expr = expr.replace(operator, "val.get_time() " + operator)
                try:
                    #print expr
                    ret = eval(expr)
                except:
                    print traceback.print_exc()
                    ret = False
        return ret


    def priority(self):
        return 1


# ex: {field: "> 100"}
# ex: {field: ["> 100", "<200"]}
class NumericFilter():
    def __init__(self):
        pass


    def match(self, node, filter):
        ret = False
        field = filter[0]
        expr = filter[1]
        val = None
        if hasattr(node, field):
            val = getattr(node, field)()
        else:
            extAttr = Attributes()
            extAttr.thisown = False
            node.extendedAttributes(extAttr)
            mextAttr = extAttr.attributes()
            if mextAttr.has_key(field):
                vval = mextAttr.value(field)
                val = vval.value()
            else:
                attr = node.staticAttributes()
                if attr.has_key(field):
                    vval = attr.value(field)
                    val = vval.value()
        if val != None:
            for operator in ["<", ">", "==", "in"]:
                expr = expr.replace(operator, str(val) + " " + operator)
            try:
                ret = eval(expr)
            except:
                ret = False
        return ret


    def priority(self):
        return 0


#filterCompilers = {"name": StringFilter, "size": IntegralFilter, "modified": TimeFilter, "accessed": TimeFilter, "created": TimeFilter, "changed": TimeFilter, "type": StringFilter, "deleted": BooleanFilter}


#filters = [field: pattern|[pattern]]
# field = name
#  default: size, name, time
#  other: based on variant
# pattern = str + operator
# operator = >, >=, <, <=, =, -

FilterTypesMapping = {typeId.String: StringFilter,
                      typeId.CArray: StringFilter,
                      typeId.Char: NumericFilter,
                      typeId.Int16: NumericFilter,
                      typeId.UInt16: NumericFilter,
                      typeId.Int32: NumericFilter,
                      typeId.UInt32: NumericFilter,
                      typeId.Int64: NumericFilter,
                      typeId.UInt64: NumericFilter,
                      typeId.Bool: BooleanFilter,
                      typeId.VTime: TimeFilter}

BaseAttributesMapping = {"name": ("name", StringFilter),
                         "deleted": ("isDeleted", BooleanFilter),
                         "file": ("isFile", BooleanFilter),
                         "folder": ("isDir", BooleanFilter),
                         "size": ("size", NumericFilter)}

class Filters():
    def __init__(self, root=None, filtersParam=None, recursive=True):
        self.filters = {}
        self.root = root
        self.recursive = recursive
        self.matchingNodes = []
        self.vfs = vfs()
        self.ai = AttributesIndexer.Get()
        if filtersParam != None:
            self.filtersParam = filtersParam
            self.compile(self.filtersParam)


    def setRootNode(self, node):
        self.root = node


    def add(self, field, filter):
        pass


    def remove(self, which):
        pass


    def list(self):
        pass


    def compile(self, filters):
        if type(filters) == types.DictType:
            attrNamesAndTypes = self.ai.attrNamesAndTypes()
            for key in filters.keys():
                #print key
                if attrNamesAndTypes.has_key(key):
                    value = filters[key]
                    attrtype = attrNamesAndTypes[key]
                    fc = FilterTypesMapping[attrtype]
                    f = fc()
                    priority = f.priority()
                    if priority not in self.filters.keys():
                        self.filters[priority] = []
                    self.filters[priority].append((f, (key, value)))
                elif BaseAttributesMapping.has_key(key):
                    value = filters[key]
                    rkey = BaseAttributesMapping[key][0]
                    fc = BaseAttributesMapping[key][1]
                    f = fc()
                    priority = f.priority()
                    if priority not in self.filters.keys():
                        self.filters[priority] = []
                    self.filters[priority].append((f, (rkey, value)))


    def process(self):
        matchedNodes = []
        if self.root != None and len(self.filters) != 0:
            if self.matchFilter(self.root):
                matchedNodes.append(self.root.this)
            for (top, dirs, files) in self.vfs.walk(self.root):
                matchedNodes.extend([f.this for f in files if self.matchFilter(f)])
                matchedNodes.extend([d.this for d in dirs if self.matchFilter(d)])
        return matchedNodes


    def matchFilter(self, node):
        for priority in [0, 1, 2]:
            if priority in self.filters.keys():
                for filter in self.filters[priority]:
                    if not filter[0].match(node, filter[1]):
                        return False
        return True
