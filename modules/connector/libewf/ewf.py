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
#  Solal Jacob <sja@digital-forensic.org>
# 

__dff_module_ewf_version__ = "1.0.0"

from api.module.module import Module
from api.module.script import Script
from api.vfs.libvfs import FdManager, fdinfo, Node, fso
from api.vfs import vfs
from api.exceptions.libexceptions import vfsError, envError
from api.types.libtypes import vtime, Variant, VMap, Argument, typeId

import os
from ctypes import CDLL, c_char_p, c_int, pointer, c_ulonglong, c_ulong, create_string_buffer, byref, pointer
from ctypes.util import find_library
from binascii import hexlify
from glob import glob

class EWFVolume(Node):
  def __init__(self, name, size, parent, fsobj):
    Node.__init__(self, name, long(size), parent, fsobj)
    self.__disown__()
    self.ewf = fsobj
    self.ssize = size
    
  def _attributes(self):
    attr = VMap()
    properties = ["case_number", "description", "examinier_name",
                      "evidence_number", "notes", "acquiry_date",
                      "system_date", "acquiry_operating_system",
                      "acquiry_software_version", "password",
                      "compression_type", "model", "serial_number", ]
 
    libewf.libewf_parse_header_values(self.ewf.ghandle, c_int(4))
    buf = create_string_buffer(1024)
    for key in properties:
       libewf.libewf_get_header_value(self.ewf.ghandle, key, buf, 1024)
       val = buf.value
       var = Variant(val)
       var.thisown = False
       attr[key] = var

    if libewf.libewf_get_md5_hash(self.ewf.ghandle, buf, 16) == 1:
       val = buf.raw[:16]
       var = Variant(hexlify(val))
       var.thisown = False
       attr['md5'] = var
    return attr	 

class EWF(fso):
  def __init__(self):
    fso.__init__(self, "ewf")
    self.__disown__()
    self.vfs = vfs.vfs()
    self.fdm = FdManager()

  def start(self, args):
    efiles = args['files'].value() 
    try :
	self.root = args["parent"].value()
    except IndexError:
	self.root = self.vfs.getnode('/')
    self.files = []
    for efile in efiles:
      efile = efile.value().path	
      try:	
	if libewf.libewf_check_file_signature(efile) == 1:
          self.files += (efile,)
	else:
	   err = Variant(str("file " + str(efile) + " is not a ewf file."))
	   err.thisown = False
	   self.res["error"] = err
	   return
      except WindowsError:
	   pass
    self.volume_array = c_char_p * len(self.files)
    self.ghandle = libewf.libewf_open(self.volume_array(*self.files), c_int(len(self.files)), c_int(1))
    if self.ghandle == 0:
       raise RuntimeError("Unable to open ewf file " + str(self.files))
    size_p = pointer(c_ulonglong(0))
    libewf.libewf_get_media_size(self.ghandle, size_p)
    self.ssize = size_p.contents.value
    name = create_string_buffer(1024) 
 
    libewf.libewf_parse_header_values(self.ghandle, c_int(4))
    if  libewf.libewf_get_header_value(self.ghandle, 'description', name, 1024) == -1 or name.value == '':
	name = 'ewf_volume'
    else:
	name = name.value
    self.node = EWFVolume(name, self.ssize, None, self)
#    libewf.libewf_close(handle) 
    self.registerTree(self.root, self.node)

  def vopen(self, node):
    handle = libewf.libewf_open(self.volume_array(*self.files), c_int(len(self.files)), c_int(1))
    if handle == 0:
       raise RuntimeError("Unable to open ewf file")

    size_p = pointer(c_ulonglong(0))
    libewf.libewf_get_media_size(handle, size_p)
    self.ssize = size_p.contents.value
    fi = fdinfo()
    fi.id = long(handle)
    fi.thisown = False
    fi.node = node
    fi.offset = 0
    fd = self.fdm.push(fi)
    return fd

  def vread(self, fd, buff, size):
    buf = create_string_buffer(size)
    fi = self.fdm.get(fd)
    retsize = libewf.libewf_read_random(fi.id, buf, c_ulong(size), c_ulonglong(fi.offset))
    if retsize <= 0:
       return (0, "")
    else :
      fi.offset += retsize
    if fi.offset > self.ssize:
	fi.offset = self.ssize
    return (retsize, buf.raw)

  def vseek(self, fd, offset, whence):
    fi = self.fdm.get(fd)
    if whence == 0:
      if offset <= self.ssize:
        fi.offset = offset
    if whence == 1:
      if fi.offset + offset > self.ssize:
        fi.offset += offset
    if whence == 2:
      fi.offset = self.ssize
    return fi.offset

  def vclose(self, fd):
    fi = self.fdm.get(fd)
    libewf.libewf_close(fi.id) 
    self.fdm.remove(fd)
    return 0

  def vtell(self, fd):
    fi = self.fdm.get(fd)
    return fi.offset

  def status(self):
    return len(self.mapped_files)

libewf = None

class ewf(Module):
  """EWF connector modules"""
  def __init__(self):
    Module.__init__(self, "ewf", EWF)
    global libewf
    if os.name == "nt":
      ewfpath = "modules\\connector\\libewf\\libewf.dll"	    
      zlibpath = "modules\\connector\\libewf\\zlib.dll"	  
      zlib = CDLL(zlibpath)
    else:
      ewfpath = find_library('ewf')
      if not ewfpath :
	ewfpath = find_library('ewf-1')
    if ewfpath:
      libewf = CDLL(ewfpath)
    if not libewf._name:
       raise Exception('loading modules', 'ewf') 
    self.conf.addArgument({"name": "files",
                           "description": "First EWF file to open",
                           "input": Argument.Required|Argument.List|typeId.Path})
    self.conf.addArgument({"name": "parent",
			   "description" : "Path where ewf will be created",
			   "input": Argument.Optional|Argument.Single|typeId.Node})
    self.tags = "Connectors"
