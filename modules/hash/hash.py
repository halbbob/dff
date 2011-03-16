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

    def getHash(self,  algorithm):
        if algorithm == "md5":
            return hashlib.md5()
        elif algorithm == "sha1":
            return hashlib.sha1()
        elif algorithm == "sha224":
            return hashlib.sha224()
        elif algorithm == "sha256":
            return hashlib.sha256()
        elif algorithm == "sha384":
            return hashlib.sha384()
        elif algorithm == "sha512":
            return hashlib.sha512()
        else:
            return -1
        
    def start(self, args):
	try:
          algorithms = args["algorithm"].value()
        except IndexError:
	  algorithms = [Variant("md5")]
        node = args["file"].value()
        for algo in algorithms:
	    algo = algo.value()
            if self.attributeHash.haveHashCalculated(node, algo):
		continue
            hash = self.hashCalc(node, algo)
            if hash != "":
                self.attributeHash.setHash(node, algo, hash)
                node.registerAttributes(self.attributeHash)
            else:
                err = Variant(str(algo + " hashing failed on " + node.absolute()))
                err.thisown = False
                self.res["error"] = err


    def hashCalc(self, node, algorithm):
        try :
            f = node.open()
            if not node.size():
                return 
        except IOError, e:
            print e
            return ""
        h = self.getHash(algorithm)
        buff = f.read(8192)
        total = len(buff) 
        while len(buff) > 0:
            self.stateinfo = node.name() + " %d" % ((total / float(node.size())) * 100) + "%" 
            h.update(buff)
            try :
                buff = f.read(8192)
                total += len(buff)
            except vfsError:
                pass
            self.stateinfo = node.name() + " %d" % ((total / float(node.size())) * 100) + "%" 
        f.close()
        return h.hexdigest()

    
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
