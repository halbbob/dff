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
# 

from api.vfs import *
from api.module.script import *
from api.module.module import *
from modules.hash.hash import HASH

import traceback

class INTEGRITY(Script):
    def __init__(self):
        Script.__init__(self, "integrity")
        self.vfs = vfs.vfs() 
        self.hash = HASH()
        self.stats = {"files": {"ok": 0, "nok": 0, "total": 0}, "dirs": {"ok": 0, "nok": 0, "total": 0},
                      "size": {"ok": 0, "nok": 0, "total": 0}, "hash": {"ok": 0, "nok": 0, "total": 0}}


    def comment(self, percent):
        if percent == 0:
            return "You are fired !!!"
        if percent < 30:
            return "Are you kidding man ?!"
        if percent < 50:
            return "You have lots of work to do"
        if percent < 70:
            return "You are on the good way"
        if percent < 80:
            return "Go on, almost done"
        if percent < 90:
            return  "last cup of coffee and that's ok"
        if percent < 100:
            return "almost done !!!"
        if percent == 100:
            return "Wonderful !!!"
        return "comment not defined"

    def getStat(self):
        print "====================================================================="
        print "                         RESULTS                                     "
        print
        for key, val in self.stats.iteritems():
            print key.upper() + ": (total " + str(val["total"]) + ")"
            if val["total"] != 0:
                ok = val["ok"] * 100 / val["total"]
                nok = val["nok"] * 100 / val["total"]
                print "  OK      --> " + str(val["ok"]) + "/" + str(val["total"]) + " (" + str(ok) + "%)"
                print "  BAD     --> " + str(val["nok"]) + "/" + str(val["total"]) + " (" + str(nok) + "%)"
                print "  COMMENT --> " + self.comment(ok)
                print
            else:
                ok = val["ok"]
                nok = val["nok"]
        print "====================================================================="
        

    def start(self, args):
        try:
            self.algorithm = args.get_string("algorithm")
            self.originalNode = args.get_node("original_content")
            self.comparedNode = args.get_node("content_to_compare")
            self.startDiff()
        except:
            traceback.print_exc()


    def startDiff(self):
        self.setBase()
        if self.originalNode.hasChildren():
            self.recursiveDiff(self.originalNode.children())
        else:
            self.stats["files"]["total"] += 1
            self.stats["files"]["ok"] += 1
            if self.isSameSize(self.originalNode, self.comparedNode):
                self.checkIntegrity(self.originalNode, self.comparedNode)
            else:
                self.stats["files"]["nok"] += 1
        self.getStat()


    def getNode(self, name):
        node = None
        try:
            node = self.vfs.getnode(name)
        except vfsError:
            traceback.print_exc()
        return node
    

    def setBase(self):
        if self.originalNode.hasChildren():
            self.originalBase = str(self.originalNode.absolute())
        else:
            self.originalBase = str(self.originalNode.path())
        if self.comparedNode.hasChildren():
            self.comparedBase = str(self.comparedNode.absolute())
        else:
            self.comparedBase = str(self.comparedNode.path())


    def diff(self, originalNode, comparedNode):
        if self.isSameSize(originalNode, comparedNode):
            self.checkIntegrity(originalNode, comparedNode)

  
    def recursiveDiff(self, originalNodes):
        dirs = []
        for originalNode in originalNodes:
            compared = str(self.comparedBase + str(originalNode.absolute()).replace(self.originalBase, "")).replace("//", "/")
            if originalNode.isDir():
                self.stats["dirs"]["total"] += 1
                comparedNode = self.getNode(compared)
                if originalNode.hasChildren():
                    dirs.append(originalNode.children())
                if comparedNode != None:
                    self.stats["dirs"]["ok"] += 1
                else:
                    print "ERROR --> folder < " + compared + " > does not exist"
                    self.stats["dirs"]["nok"] += 1
            else:
                self.stats["files"]["total"] += 1
                comparedNode = self.getNode(compared)
                if comparedNode != None:
                    self.stats["files"]["ok"] += 1
                    self.diff(originalNode, comparedNode)
                else:
                    print "ERROR --> file < " + compared + " > does not exist"
                    self.stats["files"]["nok"] += 1
        for dir in dirs:
            self.recursiveDiff(dir)


    def checkIntegrity(self, originalNode, comparedNode):
        o_hash = self.hash.hashCalc(originalNode, self.algorithm)
        c_hash = self.hash.hashCalc(comparedNode, self.algorithm)
        self.stats["hash"]["total"] += 1
        if o_hash != c_hash:
            self.stats["hash"]["nok"] += 1
            oname = str(originalNode.absolute())
            cname = str(comparedNode.absolute())
            print "ERROR --> integrity does not match between original and compared:"
            olen = len(oname)
            clen = len(cname)
            diff = abs(olen - clen)
            if olen < clen:
                print "          " + self.algorithm + "(" + oname + ") " + " " * diff + "= " + o_hash
                print "          " + self.algorithm + "(" + cname + ") = " + c_hash
            else:
                print "          " + self.algorithm + "(" + oname + ") = " + o_hash
                print "          " + self.algorithm + "(" + cname + ") " + " " * diff + "= " + c_hash
        else:
            self.stats["hash"]["ok"] += 1


    def isSameSize(self, originalNode, comparedNode):
        self.stats["size"]["total"] += 1
        if comparedNode.size() != originalNode.size():
            print "ERROR --> size differs between original and compared:"
            print "          original: " + str(originalNode.size()) + " bytes"
            print "          compared: " + str(comparedNode.size()) + " bytes"
            print "\n"
            self.stats["size"]["nok"] += 1
            return False
        else:
            self.stats["size"]["ok"] += 1
            return True


class integrity(Module):
  """Compare the content of a dff vfs to a "real" fs."""
  def __init__(self):
    Module.__init__(self, "integrity", INTEGRITY)
    self.conf.add("original_content", "node", False, "Original content.")
    self.conf.add("content_to_compare", "node", False, "Content to conpare.")
    self.conf.add("algorithm", "string", False, "Choose the hash algorithm")
    self.conf.add_const("algorithm",  "md5")
    self.conf.add_const("algorithm",  "sha1")
    self.conf.add_const("algorithm",  "sha224")
    self.conf.add_const("algorithm",  "sha256")
    self.conf.add_const("algorithm",  "sha384")
    self.conf.add_const("algorithm",  "sha512")
    self.tags = "Utils"
