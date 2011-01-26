#!/usr/bin/python -i

import api
import traceback
import sys, os

if os.name == "posix": 
    try :
        import dl
        sys.setdlopenflags(sys.getdlopenflags() | dl.RTLD_GLOBAL)
    except ImportError:
        import ctypes
        sys.setdlopenflags(sys.getdlopenflags() | ctypes.RTLD_GLOBAL)

from api.types.libtypes import *
from api.vfs.libvfs import VFS
from modules.connector.local import LOCAL
from modules.builtins.ls import LS


v = VFS.Get()

STRING_OptionalSingleInputWithFixedParam = Argument("string", OptionalSingleInputWithFixedParam|typeId.String,
                                                       "an optional string argument with fixed parameters and single input")

STRING_OptionalSingleInputWithCustomizableParam = Argument("string", OptionalSingleInputWithCustomizableParam|typeId.String,
                                                       "an optional string argument with customizable parameters and single input")

STRING_RequiredSingleInputWithFixedParam = Argument("string", RequiredSingleInputWithFixedParam|typeId.String,
                                                       "a required string argument with fixed parameters and single input")

STRING_RequiredSingleInputWithCustomizableParam = Argument("string", RequiredSingleInputWithCustomizableParam|typeId.String,
                                                       "a required string argument with customizable parameters and single input")

STRING_OptionalListInputWithFixedParam = Argument("string", OptionalListInputWithFixedParam|typeId.String,
                                                       "an optional string argument with fixed parameters and list input")

STRING_OptionalListInputWithCustomizableParam = Argument("string", OptionalListInputWithCustomizableParam|typeId.String,
                                                       "an optional string argument with customizable parameters and list input")

STRING_RequiredListInputWithFixedParam = Argument("string", RequiredListInputWithFixedParam|typeId.String,
                                                       "a required string argument with fixed parameters and list input")

STRING_RequiredListInputWithCustomizableParam = Argument("string", RequiredListInputWithCustomizableParam|typeId.String,
                                                       "an optional string argument with customizable parameters and list input")


STRING_OptionalSingleInputWithFixedParam.setEnabled(True)
print "flags:", hex(STRING_OptionalSingleInputWithFixedParam.flags())
print "type:", hex(STRING_OptionalSingleInputWithFixedParam.type())
print "inputype:", hex(STRING_OptionalSingleInputWithFixedParam.inputType())
print "paramstype:", hex(STRING_OptionalSingleInputWithFixedParam.parametersType())
print "neededtype:", hex(STRING_OptionalSingleInputWithFixedParam.requirementType())
print "=== TESTING SETTING METHOD ==="
print "    Optional --> Required"
print "    SingleInput --> ListInput"
print "    FixedParams --> CustomizableParams"
print "    String --> UInt64"
STRING_OptionalSingleInputWithFixedParam.setType(typeId.UInt64)
STRING_OptionalSingleInputWithFixedParam.setInputType(ListInput)
STRING_OptionalSingleInputWithFixedParam.setParametersType(CustomizableParam)
STRING_OptionalSingleInputWithFixedParam.setRequirementType(Required)
print "flags:", hex(STRING_OptionalSingleInputWithFixedParam.flags())
print "type:", hex(STRING_OptionalSingleInputWithFixedParam.type())
print "inputype:", hex(STRING_OptionalSingleInputWithFixedParam.inputType())
print "paramstype:", hex(STRING_OptionalSingleInputWithFixedParam.parametersType())
print "neededtype:", hex(STRING_OptionalSingleInputWithFixedParam.requirementType())

print type(STRING_OptionalSingleInputWithFixedParam)

pyListToVariant(["test", "for", "string", "weird behaviour if no =..."], 1)

res = pyListToVariant(["test", "for", "string", "weird behaviour if no =..."], 1)

print type(res)

lres = res.value()

for x in lres:
    print x

cstr = pyObjectToVariant("test", typeId.String)
print cstr

cint = pyObjectToVariant(10000000, typeId.UInt16)
print cint

l = LOCAL.local()
vm = VMap()
vm.thisown = False

n = v.GetNode("/")

print n.name()

vn = Variant(n)
vn.thisown = False

vm["parent"] = vn

vl = VList()
vl.thisown = False

#print "GENERATING Variant(Path) for"
for node in os.listdir("/home/udgover"):
    path = Path("/home/udgover/" + node)
    #print "        ", path.path
    path.thisown = False
    vp = Variant(path)
    vp.thisown = False
    vl.append(vp)

vvl = Variant(vl)
vvl.thisown = False
vm["path"] = vvl

l.start(vm)

vm = VMap()
vm.thisown = False

n = v.GetNode("/")
vn = Variant(n)
vn.thisown = False

vm["node"] = vn
#vm["option"] = 

ls = LS()
ls.start(vm)
