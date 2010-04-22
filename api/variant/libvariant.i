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
#include "node.hpp"
%}

%include "../include/export.hpp"
%include "../include/type.hpp"
//%include "../include/vtime.hpp"
%include "../include/attrib.hpp"
%include "../include/variant.hpp"
%include "../include/node.hpp"
%import "../type/libtype.i"

%template(__getValueChar) Variant::getValue<char>;
%template(__getValueInt16) Variant::getValue<int16_t>;
%template(__getValueUInt16) Variant::getValue<uint16_t>;
%template(__getValueInt32) Variant::getValue<int32_t>;
%template(__getValueUInt32) Variant::getValue<uint32_t>;
%template(__getValueInt64) Variant::getValue<int64_t>;
%template(__getValueUInt64) Variant::getValue<uint64_t>;
%template(__getValueCArray) Variant::getValue<char *>;
%template(__getValueNode) Variant::getValue<Node*>;
%template(__getValueVTime) Variant::getValue<vtime*>;

namespace std
{
  %template(__getValueString) Variant::getValue<string>;
  %template(VariantList) list<Variant*>;
  %template(VariantMap) map<string, Variant*>;
  %template(__getValueList) Variant::getValue< list<Variant *> *>;
  %template(__getValueMap) Variant::getValue< map<string, Variant *> *>;
};

%extend Variant
{
  %pythoncode
  %{
    def getValue(self):
        funcMapper = {typeId.Char: "_Variant__getValueChar",
                      typeId.Int16: "_Variant__getValueInt16",
                      typeId.UInt16: "_Variant__getValueUInt16",
                      typeId.Int32: "_Variant__getValueInt32",
                      typeId.UInt32: "_Variant__getValueUInt32",
                      typeId.Int64: "_Variant__getValueInt64",
                      typeId.UInt64: "_Variant__getValueUInt64",
                      typeId.String: "_Variant__getValueString",
                      typeId.CArray: "_Variant__getValueCArray",
                      typeId.Node: "_Variant__getValueNode",
                      typeId.VTime: "_Variant__getValueVTime",
		      typeId.List: "_Variant__getValueList",
  		      typeId.Map: "_Variant__getValueMap"}
        valType = self.type()
        if valType in funcMapper.keys():
            func = getattr(self, funcMapper[valType])
            if func != None:
                return func()
            else:
                return None
        else:
            return None
  %}
};
