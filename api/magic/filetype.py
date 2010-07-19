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
#  Solal J. <sja@digital-forensic.org>
#
import platform

import magic
from api.vfs import *
from api.env import *
from api.exceptions.libexceptions import *
from api.variant.libvariant import Variant
import os

class FILETYPE():
  class __FILETYPE():
    def __init__(self):
        self.vfs = vfs.vfs()
        self.env = env.env()
        self.magicClass = False
        print "magic load"
        try:
          self.mime = magic.Magic(True)
          self.type = magic.Magic(False)
          self.magicClass = True
        except AttributeError:
          self.mime = magic.open(magic.MAGIC_MIME)
          self.type = magic.open(magic.MAGIC_NONE)
          if os.name == "nt":
            self.mime.load("./api/magic/magic")
            self.type.load("./api/magic/magic")
          else:
            self.mime.load()
            self.type.load()

    def quit(self):
        if not self.magicClass:
          self.type.close() 
          self.mime.close()

  __instance = None

  def __init__(self):
    if FILETYPE.__instance is None:
	FILETYPE.__instance = FILETYPE.__FILETYPE()

  def __setattr__(self, attr, value):
	setattr(self.__instance, attr, value)
 
  def __getattr__(self, attr):
     return getattr(self.__instance, attr)

  def findcompattype(self, node):
      """find compatible drivers and script"""
      res = []
      self.filetype(node)
      val = self.env.vars_db["mime-type"].val_l
      idx = -1
      buff = ""
      for v in val:
        if v.type == "string":
          attr = node.staticAttributes()
          map = attr.attributes()
          try:
            nidx = str(map["type"]).find(v.get_string())
            #nidx = node.attr.smap["type"].find(v.get_string())
            if nidx > idx:
              buff  = v._from
              res.append(buff)
          except (IndexError, KeyError, AttributeError):
            nidx = str(map["mime-type"]).find(v.get_string())
            if nidx > idx:
              buff = v._from
              res.append(buff)
      return res

  def filetype(self, node):
	  buff = ""
          try :
            attr = node.staticAttributes()
            map = attr.attributes()
            map["type"]
          except (AttributeError, IndexError, KeyError):
            try:
              f = node.open()
              buff = f.read(0x2000)
              f.close()
              if not self.magicClass:
                filetype = self.type.buffer(buff)
                filemime = self.mime.buffer(buff)
              else:
                filetype = self.type.from_buffer(buff)
                filemime = self.mime.from_buffer(buff)
              vfiletype = Variant(filetype)
              vfiletype.thisown = False
              vfilemime = Variant(filemime)
              vfilemime.thisown = False
              node.setStaticAttribute("type", vfiletype)
              node.setStaticAttribute("mime-type", vfilemime)
            except vfsError:
              vdata = Variant("data")
              node.setStaticAttribute("type", vdata)
              node.setStaticAttribute("mime-type", vdata)
