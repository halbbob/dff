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
from api.events.libevents import EventHandler, event
from api.types.libtypes import typeId, VMap, Variant
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
            regex = ""
            if f[-3:] == ",i)":
                casei = True
                pattern = f[:-3]
            else:
                casei = False
                pattern = f[:-1]
            if pattern.startswith("w("):
                s = pattern[2:]
                for c in ["\\", ".", "^", "$", "+", "?", "{", "[", "]", "|", "(", ")"]:
                    s = s.replace(c, "\\"+c)
                s = s.replace("*", ".*")
                regex = "re.search(" + s
            if pattern.startswith("f("):
                regex = "re.match(" + pattern[2:]
            if pattern.startswith("re("):
                regex = "re.search(" + pattern[3:]
            if regex != "":
                regex += ", '" + val + "'"
                if casei:
                    regex += ", re.I)"
                else:
                    regex += ")"
                res.append((f, regex))
        #print res
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


    def match(self, node, filter):
        ret = False
        field = filter[0]
        expr = filter[1]
        val = None
        try:
            dtregex = re.compile("[<>]= *\d{4}-{1}\d{1,2}-{1}\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}")
            tsregex = re.compile("[<>]=* ts\(\d+\)")
            if field == "time":
                attrs = node.attributesByType(typeId.VTime)
                if len(attrs) == 0:
                    return False
                vvals = attrs.values()
            else:
                vvals = node.attributesByName(field, ABSOLUTE_ATTR_NAME)
            for vval in vvals:
                vt = vval.value()
                evalexpr = expr
                dates = []
                for dtiter in dtregex.finditer(expr):
                    begidx = dtiter.start(0)
                    endidx = dtiter.end(0)
                    match = dtiter.group(0)
                    eqidx = match.find("=")
                    operator = ""
                    if eqidx != -1:
                        operator = match[:eqidx+1]
                        strdt = match[eqidx+1:].strip()
                    #print strdt, operator
                    dt = datetime.datetime.strptime(strdt, "%Y-%m-%dT%H:%M:%S")
                    dates.append(dt)
                    evalexpr = evalexpr.replace(match, "vt.get_time()" + operator + "dates[" + str(len(dates)-1) + "]")
                for tsiter in tsregex.finditer(expr):
                    begidx = tsiter.start(0)
                    endidx = tsiter.end(0)
                    match = tsiter.group(0)
                    eqidx = match.find("=")
                    operator = ""
                    if eqidx != -1:
                        operator = match[:eqidx+1]
                        strts = match[eqidx+1:].strip()[3:-1]
                    dt = datetime.datetime.fromtimestamp(int(strts))
                    dates.append(dt)
                    evalexpr = evalexpr.replace(match, "vt.get_time()" + operator + "dates[" + str(len(dates)-1) + "]")
                if eval(evalexpr):
                    return True
            return False
        except (re.error, ValueError):
            return False


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
                         "size": ("size", NumericFilter),
                         "time": ("time", TimeFilter)}

class Filters(EventHandler):
    def __init__(self, root=None, filtersParam=None, recursive=True):
        EventHandler.__init__(self)
        self.filters = {}
        self.root = root
        self.recursive = recursive
        self.matchingNodes = []
        self.vfs = vfs()
        self.ai = AttributesIndexer.Get()
        self.__stop = False
        if filtersParam != None:
            self.filtersParam = filtersParam
            self.compile(self.filtersParam)


    def setRecursive(self, rec):
        if type(rec) == types.BooleanType:
            self.recursive = rec
        else:
            raise TypeError("Filters setRecursive method provided argument <rec> is not of type bool")


    def setRootNode(self, node):
        self.root = node


    def add(self, field, filter):
        pass


    def remove(self, which):
        pass


    def list(self):
        pass


    def Event(self, e):
        self.__stop = True


    def compile(self, filters):
        self.filters = {}
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
        e = event()
        e.thisown = False
        self.__stop = False
        if self.recursive:
            if self.root != None and len(self.filters) != 0:
                #if self.root & 0x0000ffffffffffff == 0:
                #    nodes = self.root.fsobj()
                count = 0
                totalnodes = self.root.totalChildrenCount()
                vmax = Variant(totalnodes)
                vmax.thisown = False
                e.type = 0x200
                e.value = vmax
                self.notify(e)
                if self.matchFilter(self.root):
                    count += 1
                    matchedNodes.append(self.root.this)
                #fsobjs = self.libvfs.fsobjs()
                #for fsobj in fsobjs:
                #    nodes = fsobjs.nodes()
                #    for node in nodes:
                #        if self.matchFilter(node):
                #            matchedNodes.append(node.this)
                #        count += 1
                e.type = 0x201
                for (top, dirs, files) in self.vfs.walk(self.root):
                    if self.__stop:
                        return matchedNodes
                    for d in dirs:
                        if self.__stop:
                            return matchedNodes
                        if self.matchFilter(d):
                            matchedNodes.append(d.this)
                        count += 1
                        vcount = Variant(count)
                        vcount.thisown = False
                        e.value = vcount
                        self.notify(e)
                        #print count, "/", totalnodes
                    for f in files:
                        if self.__stop:
                            return matchedNodes
                        if self.matchFilter(f):
                            matchedNodes.append(f.this)
                        count += 1
                        vcount = Variant(count)
                        vcount.thisown = False
                        e.value = vcount
                        self.notify(e)
                        #print count, "/", totalnodes
        else:
            children = self.root.children()
            count = 0
            totalnodes = len(children)
            vmax = Variant(totalnodes)
            vmax.thisown = False
            e.type = 0x200
            e.value = vmax
            self.notify(e)
            for child in children:
                if self.__stop:
                    return matchedNodes
                if self.matchFilter(child):
                    matchedNodes.append(child.this)
                count += 1
                vcount = Variant(count)
                vcount.thisown = False
                e.value = vcount
                self.notify(e)
        return matchedNodes


    def matchFilter(self, node):
        for priority in [0, 1, 2]:
            if priority in self.filters.keys():
                for filter in self.filters[priority]:
                    if not filter[0].match(node, filter[1]):
                        return False
        e = event()
        e.type = 0x202
        e.thisown = False
        vnode = Variant(node)
        vnode.thisown = False
        e.value = vnode
        self.notify(e)
        return True
