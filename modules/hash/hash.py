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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 

__dff_module_hash_version__ = "1.0.0"

import hashlib 
from api.vfs import *
from api.module.script import *
from api.module.module import *
from api.types.libtypes import Variant, VMap, Parameter, Argument, typeId
from api.vfs.libvfs import AttributesHandler

class AttributeHash(AttributesHandler): 
    def __init__(self, modname):
       AttributesHandler.__init__(self, modname)
       self.calculatedHash = {}
       self.__disown__()	

    def haveHashCalculated(self, node, algo):
       try :
          return self.calculatedHash[long(node.this)][algo]
       except KeyError:
         return None

    def setHash(self, node, algo, hash):
        if not self.calculatedHash.has_key(long(node.this)):
            self.calculatedHash[long(node.this)] = {}
        self.calculatedHash[long(node.this)][algo] = hash


    def attributes(self, node):
       m = VMap()
       hashes = self.calculatedHash[long(node.this)]
       for h in hashes.iterkeys():
           v = Variant(hashes[str(h)])
           v.thisown = False
           m[str(h)] = v
       m.thisown = False
       return m

    def __del__(self):
	pass

class HASH(Script): 
    def __init__(self):
        Script.__init__(self, "hash")   
        self.vfs = vfs.vfs()
        self.attributeHash = AttributeHash("hash") 
	self.calculatedHash = {}
        
    def start(self, args):
	try:
          algorithms = args["algorithm"].value()
        except IndexError:
	  algorithms = [Variant("md5")]
        node = args["file"].value()
        lalgorithms = []
        for algo in algorithms:
	    algo = algo.value()
            if self.attributeHash.haveHashCalculated(node, algo):
		continue
            lalgorithms.append(algo)
        hinstances, errors = self.hashCalc(node, lalgorithms)
        if len(hinstances):
            for hinstance in hinstances:
                hexdigest = hinstance.hexdigest()
                name = hinstance.name
                self.attributeHash.setHash(node, name, hexdigest)
                node.registerAttributes(self.attributeHash)
                vres = Variant(hexdigest)
                vres.thisown = False
                self.res[name] = vres
        if len(errors):
            verr = Variant(errors)
            verr.thisown = False
            self.res["error"] = verr


    def hashCalc(self, node, algorithms):
        buffsize = 10*1024*1024
        hinstances = []
        errors = ""
        if node.size() == 0:
            return ([], node.absolute() + " has no data")
        for algo in algorithms:
            if hasattr(hashlib, algo):
                func = getattr(hashlib, algo)
                instance = func()
                hinstances.append(instance)
        if len(hinstances):
            try :
                f = node.open()
            except IOError as e:
                return ([], node.absolute() + " " + e.message)
            buff = f.read(buffsize)
            total = len(buff)
            while len(buff) > 0:
                self.stateinfo = node.name() + " %d" % ((total / float(node.size())) * 100) + "%"
                for hinstance in hinstances:
                    hinstance.update(buff)
                try :
                    buff = f.read(buffsize)
                    total += len(buff)
                except IOError as e:
                    errors += "can't read between offsets " + str(total) + " and " + str(total+buffsize) + "\n"
                self.stateinfo = node.name() + " %d" % ((total / float(node.size())) * 100) + "%" 
            f.close()
        return (hinstances, errors)

    
class hash(Module):
    """Hash a file and add the results in the file attribute.
    ex: hash /myfile"""
    def __init__(self):
        Module.__init__(self, "hash", HASH)
        self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node,
                               "name": "file",
                               "description": "file to hash"
                               })
        self.conf.addArgument({"input": Argument.Optional|Argument.List|typeId.String,
                               "name": "algorithm",
                               "description": "algorithm(s) used to hash file",
                               "parameters": {"type": Parameter.NotEditable,
                                              "predefined": ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]}
                               })
        self.flags = ["single", "generic"]
        self.tags = "Hash"
