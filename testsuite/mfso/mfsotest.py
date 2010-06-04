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
#  Frederic B. <fba@digital-forensic.org>


from api.vfs import *
#from api.module.script import*
from api.module.module import Module

#from api.env import *
from api.env.libenv import *
from api.variant.libvariant import Variant
#from api.type.libtype import *
#from api.module import *
from api.vfs.libvfs import *
#from api.exceptions.libexceptions import *

from string import ascii_letters

class MfsoTestNode(Node):
    def __init__(self, letter, mfso, origin, start):
        Node.__init__(self, letter, 10, origin, mfso)
        self.thisown = False
        self.origin = origin
        self.start = start
        self.size = 10
        setattr(self, "attributes", self.attributes)
        setattr(self, "fileMapping", self.fileMapping)

    
    def fileMapping(self):
        fm = FileMapping()
        fm.thisown = False
        voffset = 0
        for i in xrange(0, 5):
            fm.push(voffset, 2, self.origin, self.start + i * 52 * 2)
            voffset += 2
        return fm

    def attributes(self):
        #print "Python node attributes requested"
        attr = Attributes()
        attr.thisown = False
        sizeattr = Variant(self.size)
        sizeattr.thisown = False
        attr.push("size", sizeattr)
        return attr


class MfsoTest(mfso):
    def __init__(self):
        mfso.__init__(self, "mfsotest")
        print dir()
        self.name = "nothing"
        self.res = results(self.name)
    
    def map(self):
        i = 0
        for letter in ascii_letters:
            MfsoTestNode(letter, self, self.parent, i)
            i+=2

    def start(self, args):
        self.parent = args.get_node("parent")
        #self.file = self.parent.open()
        self.map()
    

class mfsotest(Module):
    def __init__(self):
        Module.__init__(self, 'mfsotest', MfsoTest)
        self.conf.add("parent", "node")
        self.tags = "file system"

