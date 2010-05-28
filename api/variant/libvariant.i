/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

%module(package="api.variant") libvariant

%include "std_string.i"
%include "stdint.i"
%include "std_list.i"
%include "std_map.i"
%include "windows.i"
%include "std_except.i"

%{
#include <sys/stat.h>
#include <datetime.h>
#include "export.hpp"
#include "type.hpp"
//#include "vtime.hpp"
#include "attrib.hpp"
#include "variant.hpp"
//#include "node.hpp"
%}

%pythoncode
%{
import types
import traceback
%}

%include "../include/export.hpp"
%include "../include/type.hpp"
//%include "../include/vtime.hpp"
%include "../include/attrib.hpp"
%include "../include/variant.hpp"


%pythoncode
%{
  Variant.__origininit__ = Variant.__init__
  Variant.__init__ = Variant.__proxyinit__
  Variant.funcMapper = {typeId.Char: "_Variant__getValueChar",
                          typeId.Int16: "_Variant__getValueInt16",
                          typeId.UInt16: "_Variant__getValueUInt16",
                          typeId.Int32: "_Variant__getValueInt32",
                          typeId.UInt32: "_Variant__getValueUInt32",
                          typeId.Int64: "_Variant__getValueInt64",
                          typeId.UInt64: "_Variant__getValueUInt64",
                          typeId.String: "_Variant__getValueString",
                          typeId.CArray: "_Variant__getValueCArray",
//                      typeId.Node: "_Variant__getValueNode",
                          typeId.VTime: "_Variant__getValueVTime",
		          typeId.List: "_Variant__getVList",
  		          typeId.Map: "_Variant__getVMap"}

%}

//%include "../include/node.hpp"
%import "../type/libtype.i"

%template(__getValueChar) Variant::getValue<char>;
%template(__getValueInt16) Variant::getValue<int16_t>;
%template(__getValueUInt16) Variant::getValue<uint16_t>;
%template(__getValueInt32) Variant::getValue<int32_t>;
%template(__getValueUInt32) Variant::getValue<uint32_t>;
%template(__getValueInt64) Variant::getValue<int64_t>;
%template(__getValueUInt64) Variant::getValue<uint64_t>;
%template(__getValueCArray) Variant::getValue<char *>;
//%template(__getValueNode) Variant::getValue<Node*>;
%template(__getValueVTime) Variant::getValue<vtime*>;

%template(__getValueString) Variant::getValue<std::string>;
%template(VList) std::list<Variant*>;
%template(VMap) std::map<std::string, Variant*>;
%template(__getVList) Variant::getValue< std::list<Variant *> *>;
%template(__getVMap) Variant::getValue< std::map<std::string, Variant *> *>;

%extend Variant
{
  %pythoncode
  %{
    def __proxyinit__(self, *args):
        if len(args) == 1:
           if type(args[0]) in [type(VList), type(VMap)]:
              args[0].thisown = False
        self.__origininit__(*args)

    def __repr__(self):
        if self.type() in [typeId.Char, typeId.CArray, typeId.String]:
           buff = "'" + str(self.__getValue()) + "'"
        else:
           buff = str(self.__getValue())
        return buff

    def __getValue(self):
        valType = self.type()
        if valType in self.funcMapper.keys():
            func = getattr(self, self.funcMapper[valType])
            if func != None:
                return func()
            else:
                return None
        else:
            return None
  %}
};

%pythoncode
%{
########################################################
# Following method provides overload for VMap and VList#
########################################################
VariantType = str(type(Variant()))[8:-2]
VListType = str(type(VList()))[8:-2]
VMapType = str(type(VList()))[8:-2]

baseManagedTypes = [types.BooleanType, types.IntType, types.LongType,
                    types.StringType, types.FloatType]

def create_container_from_item(item):
    if str(type(item)).find(VariantType) != -1 or str(type(item)).find(VListType) != -1 or str(type(item)).find(VMapType) != -1:
        item.thisown = False
        return item
    elif type(item) == types.ListType:
        vl = VList()
        vl.thisown = False
        for i in item:
            container = create_container_from_item(i)
            container.thisown = False
            vl.append(container)
        return vl
    elif type(item) == types.DictType:
        vm = VMap()
        vm.thisown = False
        for key, val in item.iteritems():
            strkey = str(key)
            container = create_container_from_item(val)
            container.thisown = False
            VMap[strkey] = container
        return vm
    elif type(item) in baseManagedTypes:
        vitem = Variant(item)
        vitem.thisown = False
        return vitem
    else:
        TypeError("Management of type " + str(type(item)) + " is not implemented")


def create_variant_from_item(item):
    try:
        if str(type(item)).find(VariantType) != -1:
            return item
        else:
            vitem = create_container_from_item(item)
            if str(type(vitem)).find(VListType) != -1 or str(type(vitem)).find(VMapType) != -1:
                vvitem = Variant(vitem)
                vvitem.thisown = False
                return vvitem
            else:
                return vitem
    except(TypeError):
        traceback.print_exc()
        return None


# Wrapping methods for VList
def __vlist_proxyinit__(self, *args):
    self.__originit__()
    if len(args) >= 1:
        for arg in args:
            self.append(arg)

VList.__originit__ = VList.__init__
VList.__init__ = __vlist_proxyinit__


def vlist_append_proxy(self, item):
    vitem = create_variant_from_item(item)
    if vitem != None:
        self.__origappend__(vitem)

VList.__origappend__ = VList.append
VList.append = vlist_append_proxy


def vlist_setitem_proxy(self, *args):
    witem = create_variant_from_item(args[1])
    self.__orig_setitem__(args[0], witem)
    
VList.__orig_setitem__ = VList.__setitem__
VList.__setitem__ = vlist_setitem_proxy


def __vlist_repr__(self):
    buff = "["
    lsize = self.size()
    i = 0
    for item in self.iterator():
        i += 1
        buff += repr(item)
        if i < lsize:
            buff += ", "
    buff += "]"
    return buff


VList.__orig_repr__ = VList.__repr__
VList.__repr__ = __vlist_repr__


# Wrapping methods for VMap
def __vmap_setitem_proxy__(self, *args):
    witem = create_variant_from_item(args[1])
    self.__orig_setitem__(args[0], witem)

VMap.__orig_setitem__ = VMap.__setitem__
VMap.__setitem__ =  __vmap_setitem_proxy__


def __vmap_repr_proxy__(self):
    buff = "{"
    msize = self.size()
    i = 0
    for key, val in self.iteritems():
        i += 1
        buff += repr(key) + ": " + repr(val)
        if i < msize:
            buff += ", "
    buff += "}"
    return buff

VMap.__orig_repr__ = VMap.__repr__
VMap.__repr__ = __vmap_repr_proxy__
%}
