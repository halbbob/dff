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
import utils
import re
import types

class Completion():
    funcMapper = {typeId.Node: "complete_node",
                  typeId.Path: "complete_path"
                  }

    def __init__(self, raw_input):
        #init framework core dependencies
	self.api = ApiManager()
        self.loader = self.api.loader()
        self.vfs = self.api.vfs()
        self.confmanager = ConfigManager.Get()
        self.shell_key = [";", "<", ">", "&", "|", "&&", ";"]
	self.OS = self.api.OS()
	self.console = raw_input
 

    def complete_node(self):
        #print "complete node"
        rpath = ""
        supplied = ""
        out = {"type": "path",
               "matches": [],
               "length": 1,
               "supplied": "",
               "matched": 0}

        path = self.cur_str
        if path == "" or path[0] != "/":
            if self.vfs.getcwd().path() == "" and self.vfs.getcwd().name() == "":
                rpath = "/"
            else:
                rpath = str(self.vfs.getcwd().absolute() + "/").replace("//", "/")

        idx = path.rfind("/")
        if idx == -1:
            supplied = path
        else:
            supplied = path[idx+1:]
            rpath += path[:idx]
        try:
	    rpath = rpath.replace("\ ", " ")
            node = self.vfs.getnode(rpath)
        except OSError, e:
            out["matches"].append("")
        supplied = supplied.replace("\ ", " ")
        out["supplied"] = supplied
        if node:
            if not node.hasChildren():
                if self.cur_str == "/":
                    out["matches"].append("")
                else:
                    out["matches"].append("/")
                out["matched"] += 1
            else:
                list = node.children()
                if supplied == "":
                    for i in list:
                        name = i.name()
                        if i.hasChildren():
                            if len(name + "/") > out["length"]:
                                out["length"] = len(name + "/")
                            out["matches"].append(name + "/")
                        else:
                            if len(name) > out["length"]:
                                out["length"] = len(name)
                            out["matches"].append(name)
                        out["matched"] += 1
                else:
                    for i in list:
                        name = i.name()
                        if name.startswith(supplied) == True:
                            if i.hasChildren():
                                if len(name + "/") > out["length"]:
                                    out["length"] = len(name + "/")
                                out["matches"].append(name + "/")
                            else:
                                if len(name) > out["length"]:
                                    out["length"] = len(name)
                                out["matches"].append(name)
                            out["matched"] += 1
        return out
        

    def complete_path(self):
        #print "complete path"
        rpath = ""
        supplied = ""
        out = {"type": "path",
               "matches": [],
               "length": 1,
               "supplied": "",
               "matched": 0}
        path = self.cur_str

        if path == "":
            #rpath = os.getcwd() + "/"
            rpath = self.OS.getcwd() + '/'
        else:
            idx = path.rfind("/")
            if idx == -1:
                rpath = self.OS.getcwd() + "/"
                supplied = path

            elif idx == 0:
              supplied = path[idx+1:]  
              rpath = path[:idx+1]

            else:
                supplied = path[idx+1:]
                if path[0] != "/":
                    #rpath = os.getcwd() + "/" + path[:idx+1]
                    rpath = self.OS.getcwd() + "/" + path[:idx+1]
                else:
                    rpath = path[:idx+1]

        #directory listing
        rpath = rpath.replace("\ ", " ")
        supplied = supplied.replace("\ ", " ")
        out["supplied"] = supplied
        try:
#	    a = dircache.listdir(rpath)
            a = self.OS.listdir(rpath)
        except OSError, e:
            return
        if a:
            #completion on a path
            if supplied == "":
                for it in a:
                    #if os.path.isdir(rpath + '/' + it):
                    if self.OS.isdir(rpath + '/' + it):
                        #it = it.replace(" ", "\ ")
                        if len(it + "/") > out["length"]:
                            out["length"] = len(it + "/")
                        out["matches"].append(it + '/')
                    else:
                        #it = it.replace(" ", "\ ")
                        if len(it) > out["length"]:
                            out["length"] = len(it)
                        out["matches"].append(it)
                    out["matched"] += 1
            else:
                for it in a:
                    if it.startswith(supplied) == True:
                        #if os.path.isdir(rpath + '/' + it):
                        if self.OS.isdir(rpath + '/' + it):
                            #it = it.replace(" ", "\ ")
                            #print it
                            if len(it + "/") > out["length"]:
                                out["length"] = len(it + "/")
                            out["matches"].append(it + '/')
                        else:
                            if len(it) > out["length"]:
                                out["length"] = len(it)
                            #it = it.replace(" ", "\ ")
                            out["matches"].append(it)
                        out["matched"] += 1
        return out


    def complete_value(self):
        out = []

        if self.prev_arg.type() in [typeId.Node, typeId.Path]:
            func = getattr(self, Completion.funcMapper[self.prev_arg.type()])
            out = func()
        else:
        
            out = {"type": "predefined",
                   "matches": [],
                   "matched": 0,
                   "length": 1}
            defaults = self.prev_arg.defaults()
            for default in defaults:
                if default.type() == typeId.List:
                    for item in default.value():
                        out["matches"]
                print default
            #lmatch = len(match)
            #if lmatch > 0:
            #    out["matches"].extend(match)
            #    out["matched"] += lmatch
            #    if len(str(val)) > out["length"]:
            #        out["length"] = len(str(val))
            #if out["matched"] == 1:
            #    out = out["matches"][0]
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


    def completeKeys(self):
        out = {"type": "key", 
               "required": [],
               "optional": [],
               "length": 1,
               "matched": 0}

        arg_with_no_key = utils.get_arg_with_no_key(self.args)
        needs_no_key = utils.needs_no_key(self.parameters)
        for kparam in self.parameters.iterkeys():
            param = self.parameters[kparam]
            if (param.type() == typeId.Path or param.type() == typeId.Node) and (arg_with_no_key != -1) and (needs_no_key != None):
                pass
            else:
                arg = "--" + kparam
                if arg not in self.args and arg.startswith(self.cur_str):
                    if len(arg) > out["length"]:
                        out["length"] = len(arg)
                    if param.isOptional():
                        out["optional"].append(arg)
                    else:
                        out["required"].append(arg)
                    out["matched"] += 1

        if out["matched"] == 0:
            out = ""
        elif out["matched"] == 1:
            if len(out["required"]) == 0:
                out = out["optional"][0]
            else:
                out = out["required"][0]

        return out


    # Priority on empty
    #  -- required and neither Node nor Path
    #  -- Node or Path
    # Iter on parameters
    #   isRequired()
    #   Is Path ?
    #     - No --> continue
    #     - Yes --> nokey++
    #       - Is optional ?
    #         - Yes --> nokey++
    #         - No --> nokey++
    #   Is Node ?
    #     - No --> continue
    #     - Yes --> nokey++
    #   Is Required ?
    #     - No --> continue
    #     - Yes --> key++
    #are Path and Node in conf:
    # - Are there other required params
    #   - Yes --> complete_key
    #   - No --> if path mandatory ?
    #     - 
    # - if both optional, no completion

    def complete_empty(self):
        out = None

        if self.prev_arg != None and self.prev_arg.type() != Argument.Empty:
            out = self.complete_value()
        else:
            if len(self.remainingRequired) == 0:
                out = self.complete_value()
            elif len(self.remainingRequired) == 1:
                if self.remainingRequired[0].type() == typeId.Node:
                    out = self.complete_node()
                if self.remainingRequired[0].type() == typeId.Path:
                    out = self.complete_path()
                else:
                    out = self.complete_key()
            else:
                out = self.complete_key()
        return out


    def complete_current(self):
        out = None

        if self.cur_str.startswith("-"):
            out = self.complete_key()
        else:
            if self.prev_arg != None:
                if self.prev_arg.type() != typeId.Bool:
                    out = self.complete_value()
                else:
                    print "completion.complete_current() --> self.prev_arg == Bool"
            else:
                
                print "completion.complete_current() --> self.prev_arg == None"
            #for var in self.vars:
            #    arg = "--" + var.name()
            #    if arg == self.prev_str:
            #        out = self.complete_value()
            #    else:
            #        out = self.complete_key()
            #else:
            #arg_with_no_key = utils.get_arg_with_no_key(self.args)
            #needs_no_key = utils.needs_no_key(self.vars)
            #if self.args.index(self.cur_str) == arg_with_no_key:
            #    self.prev_arg = needs_no_key
            #    out = self.complete_value()
            #else:
            #    out = self.complete_key()

        return out


    def disambiguator(self):
        requirednodes = self.config.argumentsByFlags(typeId.Node|Argument.Required)
        #print "required nodes:"
        #for rnode in requirednodes:
        #    print rnode.name()

        optionalnodes = self.config.argumentsByFlags(typeId.Node|Argument.Optional)
        #print "optional nodes:"
        #for onode in optionalnodes:
        #    print onode.name()

        requiredpathes = self.config.argumentsByFlags(typeId.Path|Argument.Required)
        #print "required pathes:"
        #for rpath in requiredpathes:
        #    print rpath.name()

        optionalpathes = self.config.argumentsByFlags(typeId.Path|Argument.Optional)
        #print "optional pathes:"
        #for opath in optionalpathes:
        #    print opath.name()


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
        self.providedArguments = []
        self.remainingArguments = []
        self.currentArgument = None
        i = 1
        while i != len(self.lineArguments):
            print "set context:", self.lineArguments[i]
            if self.lineArguments[i].startswith("--") == True:
                argument = self.config.argumentByName(self.lineArguments[i][2:])
                if self.currentStr == self.lineArguments[i]:
                    self.currentArgument = argument
                if argument != None:
                    self.providedArguments.append(argument.name())
                    #self.remainingArguments.remove(argument.name())
            elif self.lineArguments[i-1].startswith("--") == True:
                prevarg = self.config.argumentByName(self.lineArguments[i-1][2:])
                if argument.inputType() == Argument.Empty:
                    argument = self.disambiguator()
                else:
                    argument = prevarg
            else:
                argument = self.disambiguator()
            if argument != None:
                if self.currentStr == self.lineArguments[i] or self.currentStr:
                    print "current argument:", argument.name()
                    self.currentArgument = argument
                if argument.name() not in self.providedArguments:
                    self.providedArguments.append(argument.name())
                    
            i += 1
        print "\nremaining arguments:"
        for argument in arguments:
            if argument not in self.providedArguments:
                self.remainingArguments.append(argument)
        print self.remainingArguments
        


    def dispatch(self):
        return []
                #if self.prev_str.startswith("--") != -1:
                #    self.prev_arg = self.config.argumentByName(self.prev_str[2:])
                #else:
                #    self.prev_arg = None
                #if self.cur_str == "":
                #    matches = self.complete_empty()
                #else:
                #    matches = self.complete_current()

            


    def complete(self, line, begidx):
        self.modules = self.loader.modules
        self.lineArguments, self.startIndexes, self.endIndexes = utils.split_line(line)
        matches = []
        endscope = len(self.lineArguments)
        startscope = 0
        i = 0
        self.currentStr = ""
        self.previousStr = ""
        while i != len(self.lineArguments):
            carg = self.lineArguments[i]
            argstart = self.startIndexes[i]
            argend = self.endIndexes[i]
            if carg in self.shell_key:
                if begidx <= argstart:
                    endscope = i
                else:
                    self.previousStr = ""
                    startscope = i + 1
            else:
                if begidx >= argstart:
                    if begidx <= argend:
                        self.currentStr = carg
                    else:
                        self.previousStr = carg
                        self.currentStr = ""
            i += 1
        self.lineArguments = self.lineArguments[startscope:endscope]
        print "\ncurrent context:", self.lineArguments
        print "currentstr:", self.currentStr
        print "previousstr:", self.previousStr
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
