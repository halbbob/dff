/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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
%feature("autodoc", 1); //1 = generate type for func proto, no work for typemap
%feature("docstring");

%feature("docstring") Variant
"
    Variants are designed to be a generic template type which can be used to store
    different type of data. This is useful for example while setting the extended
    attributes of a node : these attributes can be strings, integers, lists, etc.

    The type of the value is defined while creating the Variant object. To get the
    value back you just have to use the value() method.
"

%feature("docstring") Variant::__init__
"
        __init__(self) -> Variant
        __init__(self, string str) -> Variant
        __init__(self, char carray) -> Variant
        __init__(self, char c) -> Variant
        __init__(self, uint16_t us) -> Variant
        __init__(self, int16_t s) -> Variant
        __init__(self, uint32_t ui) -> Variant
        __init__(self, int32_t i) -> Variant
        __init__(self, int64_t ull) -> Variant
        __init__(self, uint64_t ll) -> Variant
        __init__(self, vtime vt) -> Variant
        __init__(self, Node node) -> Variant
        __init__(self, VList l) -> Variant
        __init__(self, VMap m) -> Variant
        __init__(self, void user) -> Variant

        Variants are designed to be a generic template type which can be used to store
        different type of data. This is useful for example while setting the extended
        attributes of a node : these attributes can be strings, integers, lists, etc.

        The type of the value is defined while creating the Variant object. To get the
        value back you just have to use the value() method.

        You can recursively used Variant. For example, you can create a map of <string, Variant \*>
        and in each Variant of the map set a list<Variant \*>. You can give a look to the
        different constructors to see which types are supported by Variants.

        The last constructor overload, which takes a void \* pointer as parameter allows
        you to use customs data type in Variant.
"

%feature("docstring") Variant::convert
"
        convert(self, uint8_t itype, void res) -> bool

        This method is used to convert the value of the variant from one type to an other.
        
        Params :
                * itype : the Id of the type into which you want to convert the value.
                * res : the buffer in which you want to store the result.
"

%feature("docstring") Variant::value
"
        Return : the value of the Variant.
"

%feature("docstring") Variant::toString
"
        toString(self) -> string

        Convert the variant value to a string

        Return : a string containing the result of the conversion.
"

%feature("docstring") Variant::toUInt16
"
        toUInt16(self) -> uint16_t

        Convert the variant value to an unsigned integer 16 bits big.

        Return : an uint16_t containing the result of the conversion.
"

%feature("docstring") Variant::toInt16
"
        toInt16(self) -> int16_t

        Convert the variant value to an integer 16 bits big

        Return : a int16_t containing the result of the conversion.
"

%feature("docstring") Variant::toUInt32
"
        toUInt32(self) -> uint32_t

        Convert the variant value to an unsigned integer 32 bits big
        Return : an uint32_t containing the result of the conversion.
"

%feature("docstring") Variant::toInt32
"
        toInt32(self) -> int32_t

        Convert the variant value to an integer 32 bits big.
        Return : an int32_t containing the result of the conversion.
"

%feature("docstring") Variant::toUInt64
"
        toUInt64(self) -> uint64_t

        Convert the variant value to an unsigned integer 64 bits big.
        Return : an uint64_t  containing the result of the conversion.
"

%feature("docstring") Variant::toInt64
"
        toInt64(self) -> int64_t

        Convert the variant value to an integer 64 bits big.

        Return : an int64_t containing the result of the conversion.
"

%feature("docstring") Variant::toBool
"
        toBool(self) -> bool

        Convert the variant value to a boolean

        Return : a boolean containing the result of the conversion.
"

%feature("docstring") Variant::type
"
        type(self) -> uint8_t

        Return the type of the value stored in the variant.
"

%feature("docstring") typeId
"
    This class is a singleton used to define the type identifier of the value of a Variant.
"

%feature("docstring") typeId::Get
"
        This method returns a pointer to the instance of THE object typeId. If it
        is called for the first time, it creates the instance before returning it.

        Return : a pointer to the typeId instance.
"

%feature("docstring") typeId::getType
"
        This method returns the ID of a type accoroding to its name. This is not the
        \"real\" typeid as defined in <typeinfo> header from the stl, but a typeid
        defined in th unum Type of the typeId class.
        
        Params :
                * args : the name of the type you want the ID

        Return : the ID of the type passed in parameter.
"

%feature("docstring") VList
"
    A list a Variant. Their use and behaviour is the same as the the std::list from the STL.
    Most of the code used in this class is generated by SWIG, who \"knows\" the
    implementation of the std::list from the STL.

    Vlists can be seen as a particular non-templated type of list where the element
    is necessarly of Variant type.

    They can be instanciated and used as in the following example (the type used for the
    variant is std::string, but it could be aby types supported by the Variant):

    
        Variant \* ex = new Variant(\"an example string\")\;

        VList   a_list(ex)\;

        a_list.push_back(new Variant(\"42\"))\; // add a new variant to the list.

        a_list.pop(); // remove the fisrt element of the list
        a_list.clear(); // empty the list

    You also can use iterators to browse elements of the VList.

    We recommend that you refer to the STL documentation of std::list for a better
    understanding of how to use the VList container.
"

%feature("doxstring") VMap
"
    A map of string and Variant. 

    This is an associative container where the key is the string and the value
    a variant.

    Their use and behaviour is the same as the the std::map from the STL.
    Most of the code used in this class is generated by SWIG, who \"knows\" the
    implementation of the std::map from the STL.

    VMaps can be seen as a particular non-templated type of map where elements
    are necessarly a pair of string and Variant.

    They can be instanciated and used as in the following example (the type used for the
    variant is std::string, but it could be aby types supported by the Variant):

    
        Variant \* ex = new Variant(\"an example string\")\;

        VList   a_map(\"key1\", ex)\;

        a_map.[\"key2\"] = new Variant(\"42\")\; // add a new variant to the list.

        a_map.clear()\; // empty the map.

    You also can use iterators to browse elements in a VMap.

    We recommend that you refer to the STL documentation of std::map for a better
    understanding of how to use the VMap container.
"

%include "std_string.i"
#ifndef WIN32
%include "stdint.i"
#else
%include "wstdint.i"
#endif
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
  Variant.funcMapper = {typeId.Char: "_Variant__Char",
                          typeId.Int16: "_Variant__Int16",
                          typeId.UInt16: "_Variant__UInt16",
                          typeId.Int32: "_Variant__Int32",
                          typeId.UInt32: "_Variant__UInt32",
                          typeId.Int64: "_Variant__Int64",
                          typeId.UInt64: "_Variant__UInt64",
                          typeId.String: "_Variant__String",
                          typeId.CArray: "_Variant__CArray",
			  typeId.Node: "_Variant__Node",
                          typeId.VTime: "_Variant__VTime",
		          typeId.List: "_Variant__VList",
  		          typeId.Map: "_Variant__VMap"}

%}

//%include "../include/node.hpp"
%import "../type/libtype.i"

%template(__Char) Variant::value<char>;
%template(__Int16) Variant::value<int16_t>;
%template(__UInt16) Variant::value<uint16_t>;
%template(__Int32) Variant::value<int32_t>;
%template(__UInt32) Variant::value<uint32_t>;
%template(__Int64) Variant::value<int64_t>;
%template(__UInt64) Variant::value<uint64_t>;
%template(__CArray) Variant::value<char *>;
%template(__Node) Variant::value<Node*>;
%template(__VTime) Variant::value<vtime*>;

%template(__String) Variant::value<std::string>;
%template(VList) std::list<Variant*>;
%template(VMap) std::map<std::string, Variant*>;
%template(__VList) Variant::value< std::list<Variant *> >;
%template(__VMap) Variant::value< std::map<std::string, Variant *> >;

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
        #if self.type() in [typeId.Char, typeId.CArray, typeId.String]:
           #buff = "'" + str(self.value()) + "'"
        #else:
        buff = str(self.value())
        return buff

    def value(self):
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
VMapType = str(type(VMap()))[8:-2]

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
