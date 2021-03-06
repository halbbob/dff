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
#  Solal J. <sja@digital-forensic.org>
#
import platform

try:
  from api.magic import magic
except:
  import magic
from api.vfs import *
from api.exceptions.libexceptions import *
from api.types.libtypes import Variant
from api.vfs.libvfs import *
import os
from libdatatype import DataTypeManager, DataTypeHandler

class MagicHandler(DataTypeHandler):
  def __init__(self, mtype, name):
     DataTypeHandler.__init__(self, name)
     self.__disown__()
     self.vfs = vfs.vfs()
     try:
	self.mime = magic.open(mtype)
     except AttributeError:
	self.mime = magic.magic_open(mtype)
     if os.name == "nt":
       import sys
       self.mime.load(sys.path[0] + "./api/magic/magic.mgc")
     else:
       try:
          self.mime.load()
       except AttributeError:
	  self.mime = magic.Magic((mtype == magic.MAGIC_MIME))

  def __del__(self):
       self.mime.close()

  def type(self, node):
    buff = ""
    try:
      f = node.open()
      buff = f.read(0x2000)
      f.close()
      try:
        filemime = self.mime.buffer(buff)
      except AttributeError:
        filemime = self.mime.from_buffer(buff)
      if filemime:
        return filemime
      return "data"
    except IOError:
      return "data"
    return "data"


try:
  magicMimeHandler = MagicHandler(magic.MAGIC_MIME, "magic mime")
except AttributeError:
  magicMimeHandler = MagicHandler(magic.MIME, "magic mime")
try:
  magicTypeHandler = MagicHandler(magic.MAGIC_NONE, "magic") 
except AttributeError:
  magicTypeHandler = MagicHandler(magic.NONE, "magic")

