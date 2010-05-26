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


%extend vlist
{
  %pythoncode
  %{
    def __proxyinit__(self, *args):
        self.__originit__(())
        if len(args) == 1:
           if type(args[0]) == types.ListType:
              try:
                 ret = self.__createVariantList(args[0])
                 newargs = (ret, )
                 self.__originit__(*newargs)
              except:
                 return
           else:
	     TypeError("argument of type " str(Types.ListType) + " must be expected but " + type(args[0]) + " provided")


    def __createPyVarToVariant(self, list):
        res = VariantList()
        res.thisown = False
        for i in list:
            v = Variant(i)
            v.thisown = False
            self.append(v)

    def __repr__(self):
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

  %}
};


/* %pythoncode */
/* %{ */
/*   VList.__originit__ = VList.__init__ */
/*   VList.__init__ = VList.__proxyinit__ */
/* %} */


           /* elif type(args[0]) == types.DictType: */
           /*    try: */
           /*       ret = self.__createVariantMap(args[0]) */
           /*       newargs = (ret, ) */
           /*       self.__originit__(*newargs) */
           /*    except(TypeError): */
           /*       return */

    /* def __createVariantMap(self, map): */
    /*     res = VariantMap() */
    /*     res.thisown = False */
    /*     for key, val in map.iteritems(): */
    /*         if type(key) != types.StringType: */
    /*            exc = types.StringType, "expected but", str(type(key)), "provided" */
    /*            raise TypeError(exc) */
    /*         else: */
    /*            vval = Variant(val) */
    /*            vval.thisown = False */
    /*            res[key] = vval */
    /*     return res */


    /* def __reprVariantMap(self): */
    /*    vmap = self.__getValue() */
    /*    buff = "{" */
    /*    msize = len(vmap) */
    /*    i = 0 */
    /*    for key, val in vmap.iteritems(): */
    /*       i += 1 */
    /*       buff += repr(key) + ": " + repr(val) */
    /*       if i < msize: */
    /*          buff += ", " */
    /*    buff += "}" */
    /*    return buff */

/* %extend append for setting thisown for each passed Variant */

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
