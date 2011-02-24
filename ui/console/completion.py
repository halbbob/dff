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
#  Christophe Malinge <cma@digital-forensic.org>
#

from api.manager.manager import ApiManager
from api.types.libtypes import typeId, Argument, Parameter, ConfigManager
import sys
import os
import dircache
import utils
import re
import types


class LineContext():
    def __init__(self):
        self.DEBUG = True
        rx = re.compile('(?=&&).')
        m = rx.search(line, 0)
        while m:
            print m.end(0)
            m = rx.search(line, m.end(0))


    def debug(self, msg):
        if self.DEBUG:
            print "  ", msg

    def splitLine(line):
        startidx = 0
        argument = ""
        i = 0
        arguments = []
        startIndexes = []
        endIndexes = []
        shell_key = [";", "<", ">", "&", "|", "&"]
        
        re.search()

        while i < len(line):
            if line[i] == " " and (line[i-1] != "\\") and (len(argument.split()) != 0):
                arguments.append(argument)
                startIndexes.append(startidx)
                endIndexes.append(i)
                argument = ""
                startidx = i
            elif line[i] in shell_key and (line[i-1] != "\\"):
                if len(argument.split()) != 0:
                    arguments.append(argument)
                    startIndexes.append(startidx)
                    endIndexes.append(i)
                argument = ""
                startidx = i
                while i < len(line) and line[i] in shell_key:
                    argument += line[i]
                    i += 1
                arguments.append(argument)
                startIndexes.append(startidx)
                endIndexes.append(i)
                if i < len(line):
                    argument = line[i]
                else:
                    argument = ""
                startidx = i
            elif len(argument.split()) == 0:
                startidx = i
                argument = line[i]
            else:
                argument = argument + line[i]
            i += 1
        if len(argument.split()) != 0:
            arguments.append(argument)
            startIndexes.append(startidx)
            endIndexes.append(i)
        return (arguments, startIndexes, endIndexes)


        self.begidx = begidx
        self.modules = self.loader.modules
        self.lineArguments, self.startIndexes, self.endIndexes = utils.split_line(line)
        matches = []
        endscope = len(self.lineArguments)
        startscope = 0
        i = 0
        self.currentStr = ""
        self.previousStr = ""
        self.currentLarg = -1
        self.previousLarg = -1
        dbg = "\n  ==== complete() ===="
        while i != len(self.lineArguments):
            carg = self.lineArguments[i]
            argstart = self.startIndexes[i]
            argend = self.endIndexes[i]
            if carg in self.shell_key:
                if begidx <= argstart:
                    endscope = i
                else:
                    self.previousStr = ""
                    self.previousLarg = -1
                    startscope = i + 1
            else:
                if begidx >= argstart:
                    if begidx <= argend:
                        self.currentStr = carg
                        self.currentLarg = i
                    else:
                        #self.previousStr = carg
                        self.previousLarg = i
                        self.currentLarg = -1
                        self.currentStr = ""
            i += 1
        dbg += "\n    processed line: " + str(self.lineArguments)
        self.lineArguments = self.lineArguments[startscope:endscope]
        dbg += "\n    processed scope: " + str(self.lineArguments)
        if self.currentLarg != -1:
            dbg += "\n    currentLarg: " + str(self.lineArguments[self.currentLarg])
        else:
            dbg += "\n    currentLarg:"
        if self.previousLarg != -1:
            dbg += "\n    previousLarg: " + str(self.lineArguments[self.previousLarg])
        else:
            dbg += "\n    previousLarg:"
        self.debug(dbg)

        if len(self.lineArguments) == 0 or (len(self.lineArguments) == 1 and self.currentStr != ""):
            matches = self.completeModules()
            if len(matches) == 0:
                print "\nmodule < " + self.currentStr + " > does not exist"
        else:
            self.config = self.confmanager.configByName(self.lineArguments[0])
            if self.config != None:
                self.setContext()
                matches = self.dispatch()
            else:
                print "\nmodule < " + self.lineArguments[0] + " > does not exist"
        if type(matches) == types.ListType and len(matches) == 1:
            return matches[0]
        else:
            return matches


    def disambiguator(self):
        requirednodes = self.config.argumentsByFlags(typeId.Node|Argument.Required)
        optionalnodes = self.config.argumentsByFlags(typeId.Node|Argument.Optional)
        requiredpathes = self.config.argumentsByFlags(typeId.Path|Argument.Required)
        optionalpathes = self.config.argumentsByFlags(typeId.Path|Argument.Optional)
        rnodes = len(requirednodes)
        onodes = len(optionalnodes)
        rpathes = len(requiredpathes)
        opathes = len(optionalpathes)

        if rnodes == 1 and rpathes == 0:
            return requirednodes[0]
        if onodes == 1 and opathes == 0 and rnodes == 0 and rpathes == 0:
            return optionalnodes[0]
        if rpathes == 1 and rnodes == 0:
            return requiredpathes[0]
        if opathes == 1 and onodes == 0 and rnodes == 0 and rpathes == 0:
            return optionalpathes[0]
        return None

    
    def setContext(self):
        arguments = self.config.argumentsName()
        self.providedArguments = {}
        self.remainingArguments = []
        self.currentArgument = None
        i = 1
        carg = None
        keylessarg = self.disambiguator()
        keylessfilled = -1
        dbg = "\n  ==== setContext() ===="
        while i != len(self.lineArguments):
            dbg += "\n    current larg: " + self.lineArguments[i]
            larg = self.lineArguments[i]
            if larg.startswith("--") == True:
                dbg += "\n      Starting with --"
                dbg += "\n      currentlarg --> " + str(self.currentLarg) + " | i --> " + str(i) + " | currentArgument --> " + str(self.currentArgument)
                if self.currentArgument != None and self.currentArgument.inputType() != Argument.Empty and self.currentLarg == i:
                    dbg += "\n      special case where provided parameters startswith -- | carg --> " + str(self.currentArgument.name()) + " | larg --> " + larg  
                    self.providedArguments[self.currentArgument.name()] = larg
                else:
                    argument = self.config.argumentByName(larg[2:])
                    if argument != None:
                        dbg += "\n      argument found: " + argument.name()
                        carg = argument
                        if carg.inputType() == Argument.Empty:
                            if self.currentLarg == -1:
                                self.currentArgument = None
                            self.providedArguments[carg.name()] = True
                        else:
                            self.currentArgument = carg
                            self.providedArguments[carg.name()] = None
                    else:
                        dbg += "\n      argument not found"
                        self.currentArgument = None
            else:
                if carg != None:
                    dbg += "\n      Not starting with --\n      carg setted --> name: " + str(carg.name()) + " input type: " + str(carg.inputType())
                    if carg.inputType() in [Argument.Single, Argument.List]:
                        if carg != keylessarg:
                            dbg += "\n      carg != keylessarg"
                            if self.providedArguments[carg.name()] == None:
                                dbg += "\n      carg parameter not setted yet. Associating parameter: " + larg
                                if self.currentLarg == i:
                                    self.currentArgument = carg
                                else:
                                    self.currentArgument = None
                                self.providedArguments[carg.name()] = larg
                            else:
                                dbg += "\n      carg parameter already setted"
                                if keylessarg != None and not self.providedArguments.has_key(keylessarg.name()):
                                    dbg += "\n      keylessarg exists and not yet registered. Associating: " + str(keylessarg.name()) + " --> " + larg
                                    carg = keylessarg
                                    if self.currentLarg == i:
                                        self.currentArgument = carg
                                    else:
                                        self.currentArgument = None
                                    self.providedArguments[keylessarg.name()] = larg
                                else:
                                    self.currentArgument = None
                                    dbg += "\n      keylessarg already exists and already setted"
                        else:
                            self.currentArgument = None
                            dbg += "\n      larg does not start with -- | carg == keylessarg but has been already provided"
                    else:
                        self.currentArgument = None
                        dbg += "\n      larg does not start with -- | carg != None | carg is Empty"
                else:
                    dbg += "\n      Not starting with --\n      carg NOT setted"
                    if keylessarg != None and not self.providedArguments.has_key(keylessarg.name()):
                        dbg += "\n      keylessarg exists and not yet registered. Associating: " + str(keylessarg.name()) + " --> " + larg
                        carg = keylessarg
                        if self.currentLarg == i:
                            self.currentArgument = carg
                        else:
                            self.currentArgument = None
                        self.providedArguments[keylessarg.name()] = larg
                    else:
                        self.currentArgument = None
                        dbg += "\n      larg does not start with -- | carg == None and keylessarg either already provided or not setted"
            i += 1
        for argument in arguments:
            if argument not in self.providedArguments.keys():
                self.remainingArguments.append(argument)
        dbg += "\n\n    provided arguments: " + str(self.providedArguments)
        dbg += "\n    remaining arguments: " + str(self.remainingArguments)
        self.debug(dbg)


class Completion():
    def __init__(self, raw_input):
        #init framework core dependencies
	self.api = ApiManager()
        self.loader = self.api.loader()
        self.vfs = self.api.vfs()
        self.confmanager = ConfigManager.Get()
        self.shell_key = [";", "<", ">", "&", "|", "&&"]
	self.console = raw_input
        self.DEBUG = True


    def currentParameter(self):
        dbg = "\n ==== currentParameter() ===="
        dbg += "\n    current str to process " + self.currentStr
        if self.currentLarg == -1:
            resstr = ""
        elif len(self.currentStr) == 1:
            resstr = self.currentStr
        elif self.currentArgument.inputType() == Argument.Single:
            resstr = self.currentStr
        else:
            beforeidx = 0
            afteridx = len(self.currentStr)
            strpos = self.begidx - self.startIndexes[self.currentLarg]
            dbg += "\n    cursor pos in current string " + str(strpos)
            dbg += "\n    current string length " + str(afteridx)
            if strpos == len(self.currentStr):
                print self.currentStr[-1:]
                beforematch = re.search('(?<!\\\)\,', self.currentStr[::-1])
                if beforematch != None:
                    beforeidx = len(self.currentStr) - beforematch.start(0)
                    dbg += "\n    beforematch @ " + str(beforeidx)
            else:
                if self.currentStr[strpos] == ",":
                    afteridx = strpos
                else:
                    aftermatch = re.search('(?<!\\\)\,', self.currentStr[strpos:])
                    if aftermatch != None:
                        afteridx = aftermatch.start(0)
                        dbg += "\n    aftermatch @ " + str(afteridx)
                beforematch = re.search('(?<!\\\)\,', self.currentStr[:strpos])
                if beforematch != None:
                    beforeidx = beforematch.start(0)
                    dbg += "\n    beforematch @ " + str(beforeidx)
            resstr = self.currentStr[beforeidx:afteridx]
        dbg += "\n    resulting str: " + resstr
        self.debug(dbg)
        return resstr



    def setPathContext(self, ctype):
        rpath = ""
        supplied = ""
        children = None
        path = self.currentParameter()
        if path == "" or path[0] != "/":
            if ctype == typeId.Node:
                rpath = self.vfs.getcwd().absolute() + "/"
            else:
                rpath = os.getcwd() + "/"
            supplied = path
        else:
            path = path.replace("//", "/")
            idx = path.rfind("/")
            if idx == -1:
                supplied = ""
                rpath = path
            else:
                supplied = path[idx+1:]
                rpath += path[:idx+1]
        rpath = rpath.replace("\ ", " ")
        supplied = supplied.replace("\ ", " ")
        if ctype == typeId.Node:
            node = self.vfs.getnode(rpath)
            if node:
                if node.hasChildren():
                    children = node.children()
                else:
                    children = []
        elif os.path.exists(rpath):
            if os.path.isdir(rpath):
                children = dircache.listdir(rpath)
            else:
                children = []
        return (path, rpath, supplied, children)


    def completePathes(self):
        out = {"type": "path",
               "matches": [],
               "length": 1,
               "supplied": "",
               "matched": 0}

        ctype = self.currentArgument.type()
        itype = self.currentArgument.inputType()
        path, rpath, supplied, children = self.setPathContext(ctype)

        dbg = "\n ==== completePathes() ===="
        if children == None:
            dbg += "\n    cannot complete with provided path"
            self.debug(dbg)
            return ""
        out["supplied"] = supplied
        dbg += "\n    path: " + path
        dbg += "\n    relative path: " + rpath
        dbg += "\n    supplied str: " + supplied
        if len(children) == 0:
            if rpath == "/":
                if path == "":
                    out["matches"].append("/")
                else:
                    out["matches"].append("")
            else:
                out["matches"].append("/")
            out["matched"] += 1
        else:
            for child in children:
                if ctype == typeId.Node:
                    name = child.name()
                else:
                    name = child
                if supplied == "" or name.startswith(supplied):
                    if (ctype == typeId.Node and child.hasChildren()) or os.path.isdir(rpath + name):
                        if len(name + "/") > out["length"]:
                            out["length"] = len(name + "/")
                        out["matches"].append(name + "/")
                    else:
                        if len(name) > out["length"]:
                            out["length"] = len(name)
                        out["matches"].append(name)
                    out["matched"] += 1
        self.debug(dbg)
        return out
        

    def completePredefined(self):
        parameter = self.currentParameter()
        out = {"type": "predefined",
               "matches": [],
               "matched": 0,
               "length": 1}
        predefs = self.currentArgument.parameters()
        for predef in predefs:
            val = str(predef.value())
            if parameter == "" or val.startswith(parameter):
                if len(val) > out["length"]:
                    out["length"] = len(val)
                out["matches"].append(val)
                out["matched"] += 1
        if out["matched"] == 1:
            out = out["matches"][0]
        return out


    def completeModules(self):
        out = {"type": "module",
               "matches": {},
               "length": {"tag": 1, "module": 1},
               "matched": 0}
        longest_tag = 1
        longest_modname = 1

        modnames = self.confmanager.configsName()
        for modname in modnames:
            if (self.currentStr == "") or (modname.startswith(self.currentStr)):
                if longest_modname < len(modname):
                    longest_modname = len(modname)
                tag = self.modules[modname].tags
                if longest_tag < len(tag):
                    longest_tag = len(tag)
                if tag not in out["matches"]:
                    out["matches"][tag] = []
                out["matches"][tag].append(modname)
                out["matched"] += 1

        out["length"]["tag"] = longest_tag
        out["length"]["module"] = longest_modname

        if out["matched"] == 1:
            out = [out["matches"][i][0] for i in out["matches"].iterkeys()]
        elif out["matched"] == 0:
            out = ""
        return out


    def completeArguments(self):
        out = {"type": "key", 
               "required": [],
               "optional": [],
               "length": 1,
               "matched": 0}

        for argname in self.remainingArguments:
            argument = self.config.argumentByName(argname)
            match = False
            if self.currentStr in ["", "-"]:
                match = True
            elif self.currentStr.startswith("--") and argname.startswith(self.currentStr[2:]):
                match = True
            if match:
                out["matched"] += 1
                if len(argname) > out["length"]:
                    out["length"] = len(argname)
                if argument.requirementType() in [Argument.Empty, Argument.Optional]:
                    out["optional"].append(argname)
                else:
                    out["required"].append(argname)
        if out["matched"] == 0:
            out = ""
        elif out["matched"] == 1:
            if len(out["required"]) == 0:
                out = out["optional"][0]
            else:
                out = out["required"][0]
            out = "--" + out
        return out


    def disambiguator(self):
        requirednodes = self.config.argumentsByFlags(typeId.Node|Argument.Required)
        optionalnodes = self.config.argumentsByFlags(typeId.Node|Argument.Optional)
        requiredpathes = self.config.argumentsByFlags(typeId.Path|Argument.Required)
        optionalpathes = self.config.argumentsByFlags(typeId.Path|Argument.Optional)
        rnodes = len(requirednodes)
        onodes = len(optionalnodes)
        rpathes = len(requiredpathes)
        opathes = len(optionalpathes)

        if rnodes == 1 and rpathes == 0:
            return requirednodes[0]
        if onodes == 1 and opathes == 0 and rnodes == 0 and rpathes == 0:
            return optionalnodes[0]
        if rpathes == 1 and rnodes == 0:
            return requiredpathes[0]
        if opathes == 1 and onodes == 0 and rnodes == 0 and rpathes == 0:
            return optionalpathes[0]
        return None


    def debug(self, msg):
        if self.DEBUG:
            print "  ", msg


    def setContext(self):
        arguments = self.config.argumentsName()
        self.providedArguments = {}
        self.remainingArguments = []
        self.currentArgument = None
        i = 1
        carg = None
        keylessarg = self.disambiguator()
        keylessfilled = -1
        dbg = "\n  ==== setContext() ===="
        while i != len(self.lineArguments):
            dbg += "\n    current larg: " + self.lineArguments[i]
            larg = self.lineArguments[i]
            if larg.startswith("--") == True:
                dbg += "\n      Starting with --"
                dbg += "\n      currentlarg --> " + str(self.currentLarg) + " | i --> " + str(i) + " | currentArgument --> " + str(self.currentArgument)
                if self.currentArgument != None and self.currentArgument.inputType() != Argument.Empty and self.currentLarg == i:
                    dbg += "\n      special case where provided parameters startswith -- | carg --> " + str(self.currentArgument.name()) + " | larg --> " + larg  
                    self.providedArguments[self.currentArgument.name()] = larg
                else:
                    argument = self.config.argumentByName(larg[2:])
                    if argument != None:
                        dbg += "\n      argument found: " + argument.name()
                        carg = argument
                        if carg.inputType() == Argument.Empty:
                            if self.currentLarg == -1:
                                self.currentArgument = None
                            self.providedArguments[carg.name()] = True
                        else:
                            self.currentArgument = carg
                            self.providedArguments[carg.name()] = None
                    else:
                        dbg += "\n      argument not found"
                        self.currentArgument = None
            else:
                if carg != None:
                    dbg += "\n      Not starting with --\n      carg setted --> name: " + str(carg.name()) + " input type: " + str(carg.inputType())
                    if carg.inputType() in [Argument.Single, Argument.List]:
                        if carg != keylessarg:
                            dbg += "\n      carg != keylessarg"
                            if self.providedArguments[carg.name()] == None:
                                dbg += "\n      carg parameter not setted yet. Associating parameter: " + larg
                                if self.currentLarg == i:
                                    self.currentArgument = carg
                                else:
                                    self.currentArgument = None
                                self.providedArguments[carg.name()] = larg
                            else:
                                dbg += "\n      carg parameter already setted"
                                if keylessarg != None and not self.providedArguments.has_key(keylessarg.name()):
                                    dbg += "\n      keylessarg exists and not yet registered. Associating: " + str(keylessarg.name()) + " --> " + larg
                                    carg = keylessarg
                                    if self.currentLarg == i:
                                        self.currentArgument = carg
                                    else:
                                        self.currentArgument = None
                                    self.providedArguments[keylessarg.name()] = larg
                                else:
                                    self.currentArgument = None
                                    dbg += "\n      keylessarg already exists and already setted"
                        else:
                            self.currentArgument = None
                            dbg += "\n      larg does not start with -- | carg == keylessarg but has been already provided"
                    else:
                        self.currentArgument = None
                        dbg += "\n      larg does not start with -- | carg != None | carg is Empty"
                else:
                    dbg += "\n      Not starting with --\n      carg NOT setted"
                    if keylessarg != None and not self.providedArguments.has_key(keylessarg.name()):
                        dbg += "\n      keylessarg exists and not yet registered. Associating: " + str(keylessarg.name()) + " --> " + larg
                        carg = keylessarg
                        if self.currentLarg == i:
                            self.currentArgument = carg
                        else:
                            self.currentArgument = None
                        self.providedArguments[keylessarg.name()] = larg
                    else:
                        self.currentArgument = None
                        dbg += "\n      larg does not start with -- | carg == None and keylessarg either already provided or not setted"
            i += 1
        for argument in arguments:
            if argument not in self.providedArguments.keys():
                self.remainingArguments.append(argument)
        dbg += "\n\n    provided arguments: " + str(self.providedArguments)
        dbg += "\n    remaining arguments: " + str(self.remainingArguments)
        self.debug(dbg)
        

    def dispatch(self):
        matches = ""
        dbg = "\n ==== dispatch() ===="
        compfunc = None
        if self.currentArgument != None:
            parg = self.providedArguments[self.currentArgument.name()]
            if parg == None or parg == self.currentStr:
                dbg += "\n    current argument to complete: " + str(self.currentArgument.name())
                if self.currentArgument.type() in [typeId.Node, typeId.Path]: 
                    compfunc = getattr(self, "completePathes")
                else:
                    compfunc = getattr(self, "completePredefined")
            else:
                compfunc = getattr(self, "completeArguments")
        else:
            dbg += "\n    no current argument to complete"
            keylessarg = self.disambiguator()
            if len(self.remainingArguments) > 0:
                dbg += "\n      remaining arguments exist --> total: " + str(len(self.remainingArguments))
                if keylessarg != None and keylessarg.name() in self.remainingArguments:
                    req = 0
                    dbg += "\n      keylessarg != None and has not been provided yet"
                    requiredargs = self.config.argumentsByRequirementType(Argument.Required)
                    for requiredarg in requiredargs:
                        rname = requiredarg.name()
                        if rname in self.remainingArguments and rname != keylessarg.name():
                            req += 1
                    if req == 0:
                        dbg += "\n      keylessarg < " + str(keylessarg.name()) + " > can be used as default"
                        self.currentArgument = keylessarg
                        if self.currentArgument.type() in [typeId.Node, typeId.Path]: 
                            compfunc = getattr(self, "completePathes")
                        else:
                            compfunc = getattr(self, "completePredefined")
                    else:
                        dbg += "\n      keylessarg can not be used as default, complete with remaining arguments"
                        compfunc = getattr(self, "completeArguments")
                else:
                    dbg += "\n      either keylessarg is None or keylessarg already used"
                    compfunc = getattr(self, "completeArguments")
            else:
                dbg += "\n    nothing to complete"
        self.debug(dbg)
        if compfunc != None:
            matches = compfunc()
            #print matches
            if self.currentStr.startswith("-") and (type(matches) in [types.ListType, types.StringType] and len(matches) == 0) or (type(matches) == types.DictType and matches["matched"] == 0):
                matches = self.completeArguments()
        return matches


    def complete(self, line, begidx):
        self.begidx = begidx
        self.modules = self.loader.modules
        self.lineArguments, self.startIndexes, self.endIndexes = utils.split_line(line)
        matches = []
        endscope = len(self.lineArguments)
        startscope = 0
        i = 0
        self.currentStr = ""
        self.previousStr = ""
        self.currentLarg = -1
        self.previousLarg = -1
        dbg = "\n  ==== complete() ===="
        while i != len(self.lineArguments):
            carg = self.lineArguments[i]
            argstart = self.startIndexes[i]
            argend = self.endIndexes[i]
            if carg in self.shell_key:
                if begidx <= argstart:
                    endscope = i
                else:
                    self.previousStr = ""
                    self.previousLarg = -1
                    startscope = i + 1
            else:
                if begidx >= argstart:
                    if begidx <= argend:
                        self.currentStr = carg
                        self.currentLarg = i
                    else:
                        #self.previousStr = carg
                        self.previousLarg = i
                        self.currentLarg = -1
                        self.currentStr = ""
            i += 1
        dbg += "\n    processed line: " + str(self.lineArguments)
        self.lineArguments = self.lineArguments[startscope:endscope]
        dbg += "\n    processed scope: " + str(self.lineArguments)
        if self.currentLarg != -1:
            dbg += "\n    currentLarg: " + str(self.lineArguments[self.currentLarg])
        else:
            dbg += "\n    currentLarg:"
        if self.previousLarg != -1:
            dbg += "\n    previousLarg: " + str(self.lineArguments[self.previousLarg])
        else:
            dbg += "\n    previousLarg:"
        self.debug(dbg)

        if len(self.lineArguments) == 0 or (len(self.lineArguments) == 1 and self.currentStr != ""):
            matches = self.completeModules()
            if len(matches) == 0:
                print "\nmodule < " + self.currentStr + " > does not exist"
        else:
            self.config = self.confmanager.configByName(self.lineArguments[0])
            if self.config != None:
                self.setContext()
                matches = self.dispatch()
            else:
                print "\nmodule < " + self.lineArguments[0] + " > does not exist"
        if type(matches) == types.ListType and len(matches) == 1:
            return matches[0]
        else:
            return matches


    def strdiff(self, str1, str2):
     i = len(str1)
     j = 0
     while j < len(str1) and j < len(str2) and str1[j] == str2[j]:
       j += 1
       i -= 1
     return len(str1) - i


    def find_longest(self, list):
     max = 0
     for str in list:
       if len(str) > max:
         max = len(str)
     return max


    def get_max_col(self, start, max):
     displaywidth = self.console.get_term_size() - start
     col = (displaywidth - (displaywidth / 6)) / max
     return col

    def insert_predefined_comp(self, text, matches):
     max_predef = matches["length"]
     col = self.get_max_col(13, max_predef)
     x = 0

     sys.stdout.write("predefined: ")
     for item in matches["matches"]:
       if x == col:
         sys.stdout.write("\n" + " " * 13)
         x = 0
       predef_arg = item + " " * (max_predef + 2 - len(item))
       x += 1
       sys.stdout.write(predef_arg)


    def insert_module_comp(self, text, matches):     
     max_tag = matches["length"]["tag"]
     max_mod = matches["length"]["module"]
     col = self.get_max_col(max_tag + 4, max_mod)
     max_ident = 0
     prev_mod = ""
     cur_mod = text
     res = ""
     idx = 0

     if matches["matched"] == 1:
       if len(matches["matches"]["required"]) == 1:
         return self.get_str(text, matches["matches"]["required"][0])
       else:
         return self.get_str(text, matches["matches"]["optional"][0])

     for tag in matches["matches"].iterkeys():
       if len(matches["matches"][tag]) > 0:
         tag_arg = tag + " " * (max_tag + 2 - len(tag)) + ": "
         sys.stdout.write(tag_arg)
         x = 0
         #sys.stdout.write(str(len(matches["modules"][tag])))
         for item in matches["matches"][tag]:
           if cur_mod != "":
             if prev_mod != "":
               _len = self.strdiff(prev_mod, item)
               if max_ident > _len:
                 max_ident = _len
             else:
               max_ident = len(item)
             prev_mod = item[:max_ident]
           if x == col:
             sys.stdout.write("\n" + " " * (max_tag + 4))
             x = 0
           mod_arg = item + " " * (max_mod + 2 - len(item))
           x += 1
           sys.stdout.write(mod_arg)
         idx += 1
         if idx < len(matches["matches"]):
           sys.stdout.write("\n")

     if max_ident > 0:
       return prev_mod[len(text):max_ident]

    def insert_path_comp(self, text, matches):
     max_path = matches["length"]
     cur_path = matches["supplied"].replace("\ ", " ")
     col = self.get_max_col(0, max_path)
     idx = 0
     filled = 0
     prev_path = ""
     max_ident = 0

     if matches["matched"] == 1:
       res = self.strdiff(cur_path, matches["matches"][0])
       comp = matches["matches"][0][res:]
       i = 0
       while i != len(comp):
         if comp[i] == " " and comp[i - 1] != "\\":
           comp = comp[:i] + "\\" + comp[i:] 
         i += 1
       return comp

     else:
       x = 0
       for path in matches["matches"]:
         if cur_path != "":
           if prev_path != "":
             res = self.strdiff(prev_path, path)
             if max_ident > res:
               max_ident = res
           else:
             max_ident = len(path)
           prev_path = path[:max_ident]
         if x == col:
           sys.stdout.write("\n")
           x = 0
         path_arg = path + " " * (max_path + 2 - len(path))
         sys.stdout.write(path_arg)
         x += 1
     if cur_path != "":
       comp = prev_path[len(cur_path):max_ident]
       i = 0
       while i != len(comp):
         if comp[i] == " " and comp[i - 1] != "\\":
           comp = comp[:i] + "\\" + comp[i:] 
         i += 1
       return comp
       #return prev_path[len(cur_path):max_ident]
     #  return self.get_str(cur_path, prev_path[:same])

    def get_str(self, text, matches):
     start = len(text)
     if start > 0:
       return matches[start:]
     else:
       return matches


    def insert_key_comp(self, text, matches):
     max_key = matches["length"]
     col = self.get_max_col(10, max_key)
     idx = 0
     filled = 0

     for type in ["required", "optional"]:
       if len(matches[type]) > 0:
         filled += 1
     
     prev_key = text
     same = 0
     for type in ["required", "optional"]:
       if len(matches[type]) > 0:
         sys.stdout.write(type + ": ")
         x = 0
         for key in matches[type]:
           same = self.strdiff(prev_key, key)
           prev_key = key
           if x == col:
             sys.stdout.write("\n" + " " * (10))
             x = 0
           key_arg = key + " " * (max_key + 2 - len(key))
           sys.stdout.write(key_arg)
           x += 1
         idx += 1
         if idx < filled:
           sys.stdout.write("\n")
     return self.get_str(text, prev_key[:same])
