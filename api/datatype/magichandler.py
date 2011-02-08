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
from api.vfs import vfs
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
     self.mime = magic.open(mtype)
     if os.name == "nt":
       import sys
       self.mime.load(sys.path[0] + "./api/datatype/magic")
     else:
       self.mime.load()

  def __del__(self):
       self.mime.close()

  def type(self, node):
    buff = ""
    try:
        f = node.open()
        buff = f.read(0x2000)
        f.close()
        filemime = self.mime.buffer(buff)
        #vfilemime = Variant(filemime)
        #vfilemime.thisown = False
        return filemime
    except IOError, e:
	#return Variant("None")
	return "None"
#	print "magic handler error reading node " + node.absolute()

 
magicMimeHandler = MagicHandler(magic.MAGIC_MIME, "magic mime")
magicTypeHandler = MagicHandler(magic.MAGIC_NONE, "magic") 

