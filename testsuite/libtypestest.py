#!/usr/bin/python -i

import api
from api.types.libtypes import *
import traceback

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
print "neededtype:", hex(STRING_OptionalSingleInputWithFixedParam.needType())
print "=== TESTING SETTING METHOD ==="
print "    Optional --> Required"
print "    SingleInput --> ListInput"
print "    FixedParams --> CustomizableParams"
print "    String --> UInt64"
STRING_OptionalSingleInputWithFixedParam.setType(typeId.UInt64)
STRING_OptionalSingleInputWithFixedParam.setInputType(ListInput)
STRING_OptionalSingleInputWithFixedParam.setParametersType(CustomizableParam)
STRING_OptionalSingleInputWithFixedParam.setNeedType(Required)
print "flags:", hex(STRING_OptionalSingleInputWithFixedParam.flags())
print "type:", hex(STRING_OptionalSingleInputWithFixedParam.type())
print "inputype:", hex(STRING_OptionalSingleInputWithFixedParam.inputType())
print "paramstype:", hex(STRING_OptionalSingleInputWithFixedParam.parametersType())
print "neededtype:", hex(STRING_OptionalSingleInputWithFixedParam.needType())

res = pyListToVariant(["test", "for", "string", "weird behaviour if no =..."], 1)
