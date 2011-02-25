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

from api.types.libtypes import typeId, Argument, Parameter, ConfigManager
from api.vfs.vfs import vfs
from api.loader.loader import loader
import sys, os, dircache, utils, re, types


class Context():
    def __init__(self, DEBUG = False):
        self.DEBUG = DEBUG
        self.confmanager = ConfigManager.Get()
        self.config = None
        self.keylessarg = None
        self.currentArgument = None
        self.providedArguments = {}
        self.remainingArguments = []
        self.threaded = False
        self.currentStr = ""
        self.vfs = vfs()
        self.currentStrScope = 0
        self.paramsplit = re.compile('(?<!\\\)\,')
        self.badargs = []


    def debug(self, dbg):
        if self.DEBUG:
            print dbg


    def __makeParameter(self, argument, parameter):
        if argument.type() == typeId.Node:
            n = self.vfs.getnode(parameter)
            if n:
                return n
            else:
                raise ValueError("Node " + str(parameter)  + " provided to argument < " + argname + " >")
        else:
            return parameter


    def makeArguments(self):
        command = {}
        dbg = "\n ==== Context.makeCommand() ===="
        if len(self.badargs) > 0:
            raise KeyError("cannot generate config for module < " + self.config.origin() + " > The following arguments do not exist: " + str(self.badargs)) 
        for argname in self.providedArguments.keys():
            argument = self.config.argumentByName(argname)
            parameters = self.providedArguments[argname]
            if argument.inputType() == Argument.List:
                l = []
                iterator = self.paramsplit.finditer(parameters)
                itcount = 0
                previdx = 0
                for match in iterator:
                    itcount += 1
                    pos = match.span()
                    parameter = parameters[previdx:pos[0]]
                    previdx = pos[1]
                    dbg += "\n    adding parameter: < " + str(parameter) + " > to list"
                    try:
                        realparam = self.__makeParameter(argument, parameter)
                        l.append(realparam)
                    except:
                        raise
                if itcount == 0 or previdx != len(parameters):
                    dbg += "\n    adding parameter: < " + parameters[previdx:] + " > to list"
                    try:
                        realparam = self.__makeParameter(argument, parameters[previdx:])
                        l.append(parameters[previdx:])
                    except:
                        raise
                command[argname] = l
            else:
                dbg += "\n    adding parameter: < " + str(parameters)
                try:
                    realparam = self.__makeParameter(argument, parameters)
                    command[argname] = realparam
                except:
                    raise
        if self.DEBUG:
            dbg += "\n    resulting command arguments:"
            for argname in command.keys():
                dbg += "\n      " + argname + " --> " + str(command[argname])
        self.debug(dbg)
        return command
                
    

    def dump(self):
        buff = "\n ==== Context.dump() ===="
        buff += "\n    associated config: "
        if self.config != None:
            buff += self.config.origin()
            lparg = len(self.providedArguments)
            buff += "\n    provided arguments: " + str(lparg)
            if lparg != 0:
                for argname in self.providedArguments.keys():
                    buff += "\n      " + argname + " --> " + str(self.providedArguments[argname])
            lrarg = len(self.remainingArguments)
            buff += "\n    remaining arguments: " + str(lrarg)
            if lrarg != 0:
                for argname in self.remainingArguments:
                    buff += "\n      " + argname
            buff += "\n    threaded: " + str(self.threaded)
        else:
            buff += " None"
        buff += "\n    currentStr: " + self.currentStr
        buff += "\n    currentStrScope: " + str(self.currentStrScope) 
        return buff
        

    def disambiguator(self):
        requirednodes = self.config.argumentsByFlags(typeId.Node|Argument.Required)
        optionalnodes = self.config.argumentsByFlags(typeId.Node|Argument.Optional)
        requiredpathes = self.config.argumentsByFlags(typeId.Path|Argument.Required)
        optionalpathes = self.config.argumentsByFlags(typeId.Path|Argument.Optional)
        rnodes = len(requirednodes)
        onodes = len(optionalnodes)
        rpathes = len(requiredpathes)
        opathes = len(optionalpathes)

        dbg = "\n ==== Context.disambiguator() ===="
        if rnodes == 1 and rpathes == 0:
            self.keylessarg = requirednodes[0]
        if onodes == 1 and opathes == 0 and rnodes == 0 and rpathes == 0:
            self.keylessarg = optionalnodes[0]
        if rpathes == 1 and rnodes == 0:
            self.keylessarg = requiredpathes[0]
        if opathes == 1 and onodes == 0 and rnodes == 0 and rpathes == 0:
            self.keylessarg = optionalpathes[0]
        if self.keylessarg != None:
            dbg += "\n    keylessarg exists and has been setted to < " + str(self.keylessarg.name()) + " >"
        else:
            dbg += "\n    keylessarg does not exist"
        self.debug(dbg)


    def parameterToken(self, token, current):
        dbg = "==== Context.parameterToken() ===="
        if self.currentArgument == None:
            dbg += "\n    currentArgument == None"
            if self.keylessarg != None and self.keylessarg.name() in self.remainingArguments:
                dbg += "\n    keylessarg exists and not setted yet. " + str(self.keylessarg.name()) + " --> " + token
                self.providedArguments[self.keylessarg.name()] = token
                self.remainingArguments.remove(self.keylessarg.name())
                self.currentArgument = self.keylessarg
        elif self.providedArguments[self.currentArgument.name()] == None or current:
            dbg += "\n    currentArgument exists and not setted yet. " + str(self.currentArgument.name()) + " --> " + token
            self.providedArguments[self.currentArgument.name()] = token
            self.remainingArguments.remove(self.currentArgument.name())
        else:
            dbg += "\n    currentArgument already setted"
            self.currentArgument = None
        self.debug(dbg)

    def __argumentToken(self, token, current):
        dbg = "\n ==== Context.__argumentToken() ===="
        argument = self.config.argumentByName(token[2:])
        if argument != None:
            argname = argument.name()
            dbg += "\n      argument found: " + argname
            if argname in self.remainingArguments:
                self.providedArguments[argname] = None
                if argument.inputType() == Argument.Empty:
                    self.remainingArguments.remove(argname)
                    self.currentArgument = None
                else:
                    self.currentArgument = argument
            else:
                dbg += "\n      argument < " + argname + " > already provided"
        else:
            self.badargs.append(token)
            dbg += "\n      argument not found"
            self.currentArgument = None


    def argumentToken(self, token, current):
        dbg = "\n ==== Context.argumentToken() ===="
        if self.currentArgument != None:
            if self.currentArgument.inputType() != Argument.Empty:
                dbg += "\n    token starts with -- and currentArgument != None and is not a switch"
                argname = self.currentArgument.name()
                if self.providedArguments[argname] == None:
                    dbg += "\n    currentArgument exists and not setted yet. " + str(argname) + " --> " + token
                    self.remainingArguments.remove(argname)
                    self.providedArguments[argname] = token
                else:
                    self.__argumentToken(token, current)
            else:
                self.remainingArguments.remove(argname)
                self.providedArguments[argname] = None
                self.currentArgument = None
        else:
            self.__argumentToken(token, current)
        self.debug(dbg)


    def configToken(self, token):
        self.config = self.confmanager.configByName(token)
        if self.config != None:
            self.disambiguator()
            argsname = self.config.argumentsName()
            for argname in argsname:
                self.remainingArguments.append(argname)


    def addToken(self, token, current, begidx, startidx):
        dbg = "\n ==== Context.addToken() ===="
        if current:
            self.currentStr = token
            self.currentStrScope = begidx - startidx
        if self.config == None:
            if not current:
                self.configToken(token)
        else:
            if token.startswith("--"):
                self.argumentToken(token, current)
            else:
                self.parameterToken(token, current)



class LineParser():
    def __init__(self, DEBUG = False):
        self.DEBUG = DEBUG
        self.ctxs = []
        self.shellKeys = [";", "<", ">", "&", "|"]


    def debug(self, msg):
        if self.DEBUG:
            print "  ", msg


    def currentContext(self):
        if self.scopeCtx >= 0:
            return self.contexts[self.scopeCtx]
        return None


    def manageShellKeys(self, key, startidx, endidx):
        dbg = "\n ==== LineParser.manageShellKeys() ===="
        if key == "&":
            dbg += "\n    & found"
            dbg += "\n    begidx: " + str(self.begidx)
            dbg += "\n    endidx: " + str(endidx)
            self.contexts[self.ctxpos].threaded = True
            if self.begidx >= endidx and endidx != len(self.line):
                dbg += "\n    incrementing ctxpos"
                ctx = Context(self.DEBUG)
                self.contexts.append(ctx)
                self.ctxpos += 1
                self.scopeCtx = self.ctxpos
        elif key == "&&":
            self.contexts.append(Context(self.DEBUG))
            self.ctxpos += 1
            if self.begidx == startidx + 1:
                self.scopeCtx = self.ctxpos
                dbg += "\n    key found and begidx in the middle of " + key
                #self.contexts.append(Context(self.DEBUG))
        self.debug(dbg)


    def manageToken(self, token, startidx, endidx):
        dbg = "\n ==== LineParser.manageToken() ===="
        dbg += "\n    token found <" + token + ">"
        dbg += "\n    begidx: " + str(self.begidx)
        dbg += "\n    startidx: " + str(startidx)
        dbg += "\n    endidx: " + str(endidx)
        current = False
        if self.begidx >= startidx and self.begidx <= endidx:
            dbg += "\n      cursor pos is in token: " + token + " @ " + str(self.begidx - startidx)
            self.scopeCtx = self.ctxpos
            current = True
        self.debug(dbg)
        self.contexts[self.ctxpos].addToken(token, current, self.begidx, startidx)



    def makeCommands(self, line):
        line = line.rstrip()
        begidx = len(line)
        self.makeContexts(line, begidx)
        commands = []
        dbg = "\n ==== LineParser.makeCommands() ===="
        for context in self.contexts:
            try:
                commands.append((context.config.origin(), context.makeArguments(), context.threaded))
            except (KeyError, ValueError):
                raise
        if self.DEBUG:
            dbg += "\n    stacked commands:"
            for command in commands:
                dbg += "\n      command name: " + command[0]
                dbg += "\n      arguments: " + str(command[1])
                dbg += "\n      to thread: " + str(command[2]) + "\n"
        self.debug(dbg)
        return commands


    def makeContexts(self, line, begidx = -1):
        self.begidx = begidx
        self.contexts = []
        self.scopeCtx = -1
        self.line = line
        self.ctxpos = 0
        startidx = 0
        i = 0
        token = ""

        dbg = "\n ==== LineParser.makeContext() ===="
        dbg += "\n    line: |" + line + "|"
        dbg += "\n    begidx: " + str(begidx)
        if len(line) != 0:
            ctx = Context(self.DEBUG)
            self.contexts.append(ctx)
            while i < len(line):
                if line[i] == " " and (line[i-1] != "\\") and (len(token.split()) != 0):
                    self.manageToken(token, startidx, i)
                    token = ""
                    startidx = i
                elif line[i] in self.shellKeys and (line[i-1] != "\\"):
                    if len(token.split()) != 0:
                        self.manageToken(token, startidx, i)
                    token = ""
                    startidx = i
                    key = ""
                    while i < len(line) and line[i] in self.shellKeys:
                        key += line[i]
                        i += 1
                    self.manageShellKeys(key, startidx, i)
                    startidx = i
                    if i < len(line):
                        token = line[i]
                    else:
                        token = ""
                    startidx = i
                elif len(token.split()) == 0:
                    startidx = i
                    token = line[i]
                else:
                    token = token + line[i]
                i += 1
            if len(token.split()) != 0:
                self.manageToken(token, startidx, i)
                dbg += "\n    last token found <" + token + ">"
                dbg += "\n    startidx: " + str(startidx)
                dbg += "\n    endidx: " + str(i)
            if self.begidx == len(line):
                self.scopeCtx = self.ctxpos

            if self.DEBUG:
                dbg += "\n    current context: "
                if self.contexts[self.scopeCtx].config:
                    dbg += str(self.contexts[self.scopeCtx].config.origin())
                else:
                    dbg += "None"
                dbg += "\n    scopeCtx: " + str(self.scopeCtx)
                dbg += "\n    ctxpox: " + str(self.ctxpos)
                print dbg
                for ctx in self.contexts:
                    print ctx.dump()
                print 


class Completion():
    def __init__(self, console, DEBUG = False):
        self.DEBUG = DEBUG
	self.console = console
        self.lp = LineParser(self.DEBUG)
        self.confmanager = ConfigManager.Get()
        self.loader = loader()
        self.vfs = vfs()


    def currentParameter(self):
        dbg = "\n ==== currentParameter() ===="
        dbg += "\n    current str to process: |" + self.context.currentStr + "|"
        resstr = ""
        if len(self.context.currentStr) in  [0, 1] or self.context.currentArgument.inputType() == Argument.Single:
            resstr = self.context.currentStr[:self.context.currentStrScope]
        else:
            endidx = self.context.currentStrScope
            dbg += "\n    cursor pos in current string " + str(endidx)
            iterator = re.finditer('(?<!\\\)\,', self.context.currentStr)
            startidx = 0
            for match in iterator:
                pos = match.span()
                dbg += "\n    " + str(pos)
                dbg += "\n    " + str(endidx)
                if pos[1] <= endidx:
                    startidx = pos[1]
            dbg += "\n    startidx: " + str(startidx)
            dbg += "\n    endidx: " + str(endidx)
            resstr = self.context.currentStr[startidx:endidx]
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
            path = path.replace("//", "/")
            if path.rfind("/") != -1:
                supplied = ""
                rpath += path
            else:
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

        ctype = self.context.currentArgument.type()
        itype = self.context.currentArgument.inputType()
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
                if rpath[-1] != "/":
                    out["matches"].append("/")
                else:
                    out["matches"].append("")
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
        predefs = self.context.currentArgument.parameters()
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
            if (self.context == None) or modname.startswith(self.context.currentStr[:self.context.currentStrScope]) or self.context.currentStr[:self.context.currentStrScope] == "":
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

        for argname in self.context.remainingArguments:
            argument = self.context.config.argumentByName(argname)
            match = False
            if self.context.currentStr[:self.context.currentStrScope] in ["", "-"]:
                match = True
            elif self.context.currentStr.startswith("--") and argname.startswith(self.context.currentStr[2:self.context.currentStrScope]):
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


    def debug(self, msg):
        if self.DEBUG:
            print "  ", msg


    def dispatch(self):
        matches = ""
        dbg = "\n ==== dispatch() ===="
        compfunc = None
        if self.context.currentArgument != None:
            parg = self.context.providedArguments[self.context.currentArgument.name()]
            dbg += "\n    currentArgument exists: " + str(self.context.currentArgument.name())
            dbg += "\n    associated parameter: " + str(parg)
            if parg == None or parg == self.context.currentStr:
                dbg += "\n    completing parameters for argument: " + str(self.context.currentArgument.name())
                if self.context.currentArgument.type() in [typeId.Node, typeId.Path]:
                    compfunc = getattr(self, "completePathes")
                else:
                    compfunc = getattr(self, "completePredefined")
            else:
                dbg += "\n    completing argument for currentStr: " + str(self.context.currentStr) 
                compfunc = getattr(self, "completeArguments")
        else:
            dbg += "\n    no current argument to complete"
            if len(self.context.remainingArguments) > 0:
                dbg += "\n      remaining arguments exist --> total: " + str(len(self.context.remainingArguments))
                if self.context.keylessarg != None and self.context.keylessarg.name() in self.context.remainingArguments:
                    req = 0
                    dbg += "\n      keylessarg != None and has not been provided yet"
                    requiredargs = self.context.config.argumentsByRequirementType(Argument.Required)
                    for requiredarg in requiredargs:
                        rname = requiredarg.name()
                        if rname in self.context.remainingArguments and rname != self.context.keylessarg.name():
                            req += 1
                    if req == 0 and not self.context.currentStr.startswith("--"):
                        dbg += "\n      keylessarg < " + str(self.context.keylessarg.name()) + " > can be used as default"
                        self.context.currentArgument = self.context.keylessarg
                        if self.context.currentArgument.type() in [typeId.Node, typeId.Path]: 
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
        return matches


    def complete(self, line, begidx):
        self.modules = self.loader.modules
        self.lp.makeContexts(line, begidx)
        self.context = self.lp.currentContext()
        matches = ""
        if self.context == None:
            matches = self.completeModules()
        elif self.context.config == None:
            matches = self.completeModules()
            if len(matches) == 0:
                print "\nmodule < " + self.context.currentStr + " > does not exist"
        else:
            if self.context.currentStr != self.context.config.origin():
                matches = self.dispatch()

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
