# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2010 ArxSys
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

import hashlib 
from api.vfs import *
from api.module.script import *
from api.module.module import *
from api.variant.libvariant import Variant

class HASH(Script):
    def __init__(self):
        Script.__init__(self, "hash")    
        self.vfs = vfs.vfs() 

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
        node = args.get_node("file")
	try :
          algorithm = args.get_string("algorithm")
	except envError:
	  algorithm = "md5"
        if algorithm == "":
	  algorithm = "md5"
        attr = node.staticAttributes()
        res = ""
        algmap = "hash-" + algorithm
        try:
            map = attr.attributes()
            file_hash = map[algmap]
            res = file_hash + "  " + node.absolute()
        except:
            file_hash = self.hashCalc(node, algorithm)
            if file_hash != "":
                value = Variant(file_hash)
                value.thisown = False
                node.setStaticAttribute(algmap, value)
                res = file_hash + "  " + node.absolute()
            else:
                res = algorithm + " hashing failed on " + node.absolute()  
        self.res.add_const("result", res)


    def hashCalc(self, node, algorithm):
        try :
            f = node.open()
        except vfsError, e:
            print e.error, node.absolute()
            return ""
        h = self.getHash(algorithm)
        buff = f.read(8192)
	total = len(buff) 
        while len(buff) > 0:
	    self.stateinfo = "%d" % ((total / float(node.size())) * 100) + "%" 
            h.update(buff)
            try :
                buff = f.read(8192)
		total += len(buff)
            except vfsError:
                pass
	self.stateinfo = "%d" % ((total / float(node.size())) * 100) + "%" 
        f.close()
        return h.hexdigest()


class hash(Module):
  """Hash a file and add the results in the file attribute.
ex: hash /myfile"""
  def __init__(self):
    Module.__init__(self, "hash", HASH)
    self.conf.add("file", "node", False, "file to hash.")
    self.conf.add("algorithm", "string", True, "Choose the hash algorithm")
    self.conf.add_const("algorithm",  "md5")
    self.conf.add_const("algorithm",  "sha1")
    self.conf.add_const("algorithm",  "sha224")
    self.conf.add_const("algorithm",  "sha256")
    self.conf.add_const("algorithm",  "sha384")
    self.conf.add_const("algorithm",  "sha512")
    self.tags = "Hash"
