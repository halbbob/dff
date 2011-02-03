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

try:
    l.start(**vm)
except TypeError:
    l.start(vm)

vm = VMap()
vm.thisown = False

n = v.GetNode("/")
vn = Variant(n)
vn.thisown = False

vm["node"] = vn
vb = Variant(True)
vb.thisown = True
vm["long"] = vb
vm["recursive"] = vb

ls = LS()
ls.start(**vm)

import time, traceback

vlist = VList()
vlist2 = VList()
pylist = []
pylist2 = []
vmap = VMap()
vmap2 = VMap()
pymap = {}
pymap2 = {}

nbitem = 10

print "=" * 50
print "Creating vlist, vvlist, pylist, pylist2, vmap, vvmap, pymap and pymap2 with", nbitem, "items :"
t = time.time()
for i in xrange(0, nbitem):
    vlist.append(i)
    vlist2.append(i)

    pylist.append(i)
    pylist2.append(i)

    vmap[str(i)] = i
    vmap2[str(i)] = i

    pymap[str(i)] = i
    pymap2[str(i)] = i

pylist2[nbitem - 1] = 0
vlist2[nbitem-1] = nbitem

pymap2[str(nbitem - 1)] = 0
vmap2[str(nbitem-1)] = nbitem

vvlist = Variant(vlist)
vvlist2 = Variant(vlist2)

vvmap = Variant(vmap)
vvmap2 = Variant(vmap2)

vstr1 = Variant("str1")
vstr2 = Variant("str2")

vmaplist = VMap()
vmaplist2 = VMap()

vmaplist["LIST"] = vvlist
vmaplist["str"] = vstr1

vmaplist2["LIST"] = vvlist2
vmaplist2["str"] = vstr2

vvmaplist = Variant(vmaplist)
vvmaplist2 = Variant(vmaplist2)

vlistmap = VList()
vlistmap2 = VList()
vlistmap.append(vmap)
vlistmap2.append(vmap2)

vvlistmap = Variant(vlistmap)
vvlistmap2 = Variant(vlistmap2)

extime = time.time() - t
print "exec time:", extime
print ("=" * 50) + "\n"

tests = [
    "vstr1 == vstr1", "vstr2 == vstr1", "vstr1 == 'str1'", "vstr1 == ''", "vstr1 == 'different'",

    "vlist == vlist", "vlist == vlist2", "vlist == pylist", "vlist == pylist2",
    "vvlist == vvlist", "vvlist == vvlist2",  "vvlist == vlist", "vvlist == vlist2", "vvlist == pylist", "vvlist == pylist2",
    "nbitem - 1 in vlist", "Variant(nbitem - 1) in vlist", "nbitem in vlist", "Variant(nbitem) in vlist",

    "vmap == vmap", "vmap == vmap2", "vmap == pymap", "vmap == pymap2",
    "vvmap == vvmap", "vvmap == vvmap2", "vvmap == vmap", "vvmap == vmap2", "vvmap == pymap", "vvmap == pymap2",
    
    "vlistmap == vlistmap", "vlistmap == vlistmap2", 
    "vvlistmap == vvlistmap", "vvlistmap == vvlistmap2",

    "vmaplist == vmaplist", "vmaplist == vmaplist2",
    "vvmaplist == vvmaplist", "vvmaplist == vvmaplist2"]


print "=" * 50
print "Starting tests:"
print tests
print ("=" * 50) + "\n"

for test in tests:
    print "=" * 50
    print "Current test ---> " + test
    idx = test.find("==")
    key = "=="
    if idx == -1:
        idx = test.find("in")
        key = "in"
    print eval(test[:idx])
    print "\n", 25*" ", key, "\n"
    print eval(test[idx+2:]), "\n"
    t = time.time()
    try:
        res = eval(test)
    except:
        print "error with test", test
        traceback.print_exc(file=sys.stdout)
    extime = time.time() - t
    print "\n< " + test + " > terminated"
    print "result:" + (" " * 3), res
    print "exec time:", extime
    print ("=" * 50) + "\n"

print "==", Variant(123456) == Variant(123456), 123456 == 123456
print "!=", Variant(123456) != Variant(123456), 123456 != 123456
print ">", Variant(123456) > Variant(123456), 123456 > 123456
print "<", Variant(123456) < Variant(123456), 123456 < 123456
print ">=", Variant(123456) >= Variant(123456), 123456 >= 123456
print "<=", Variant(123456) <= Variant(123456), 123456 <= 123456
