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
#  Solal Jacob <sja@digital-forensic.org>
# 

from api.module.module import Module
from api.module.script import Script
from api.vfs.libvfs import FdManager, fdinfo, Node, mfso
from api.vfs import vfs
from api.exceptions.libexceptions import vfsError
from api.type.libtype import vtime
from api.variant.libvariant import Variant

import traceback
import mzipfile

class ZipNode(Node):

  __slots__ = (
    'orig_filename',
    'filename',
    'compress_type',
    'comment',
    'extra',
    'create_system',
    'create_version',
    'extract_version',
    'reserved',
    'flag_bits',
    'volume',
    'internal_attr',
    'external_attr',
    'header_offset',
    'CRC',
    'compress_size',
    '_raw_time',
    )

  def __init__(self, name, size, parent, fsobj, zipfile):
    Node.__init__(self, name, size, parent, fsobj)
    self.zipfile = zipfile
    self.setFile()
    #setattr(self, "extendedAttributes", self.extendedAttributes)
    #setattr(self, "createdTime", self.createdTime)
    self.fsobj = fsobj


  def createdTime(self, vt):
    zipattr = self.fsobj.zipcontent.getinfo(self.zipfile)
    vt.year = zipattr.date_time[0]
    vt.month = zipattr.date_time[1]
    vt.day = zipattr.date_time[2]
    vt.hour = zipattr.date_time[3]
    vt.minute = zipattr.date_time[4]
    vt.second = zipattr.date_time[5]


  def extendedAttributes(self, attr):
    zipattr = self.fsobj.zipcontent.getinfo(self.zipfile)
    for key in ZipNode.__slots__:
      val = getattr(zipattr, key)
      if key != "date_time":
        vval = Variant(val)
        vval.thisown = False
        attr.push(key, vval)


class UNZIP(mfso):
  def __init__(self):
    mfso.__init__(self, "unzip")
    self.vfs = vfs.vfs()
    self.fdm = FdManager()
    self.origin = None
    self.zipcontent = None
    self.file = None
    self.opened_fds = {}
    self.mapped_files = {}


  def start(self, args):
    try:
      origin = args.get_node('file')
      self.makeZipTree(origin)
    except (envError, vfsError):
      formatted_lines = traceback.format_exc().splitlines()
      self.res.add_const("error", formatted_lines[-1])

  
  def makeZipTree(self, origin):
    self.origin = origin
    self.file = self.origin.open()
    self.zipcontent = mzipfile.ZipFile(self.file)
    for zipfile in self.zipcontent.namelist():
      idx = zipfile.rfind("/")
      if idx != -1:
        path = zipfile[:idx]
        filename = zipfile[idx+1:]
      else:
        path = ""
        filename = zipfile
      parent = self.vfs.getnode(self.origin.absolute() + "/" + path)
      if parent == None:
        print path
        parent = self.makeDirs(path)
      attr = self.zipcontent.getinfo(zipfile)
      node = ZipNode(filename, attr.file_size, parent, self, zipfile)
      node.__disown__()
      #  zinfo = zf.getinfo(uzfile)
      #  print uzfile, dir(zinfo)
      #  self.shm.addnode(node, uzfile)
      #  if zinfo.file_size > 0:
      #    self.shm.addnode(node, uzfile)
          #dfilename = node.absolute() + "/" + uzfile
          #dnode = self.touch(dfilename)
          #dfile = dnode.open()
          #dfile.write(zf.read(uzfile))
          #dfile.close()

  def makeDirs(self, folders):
    sfolders = folders.split("/")
    prev = self.origin
    for folder in sfolders:
      node = self.vfs.getnode(prev.absolute() + "/" + folder)
      if node == None:
        node = Node(folder, 0, prev, self)
        node.setDir()
        node.__disown__()
      prev = node
    return node


  def mappedFile(self, zipfile):
    info = self.zipcontent.getinfo(zipfile)
    buff = ""
    if info.file_size > 0:
      buff = self.zipcontent.read(zipfile)
    return buff


  def nodeToZipFile(self, node):
    abs = node.absolute()
    orig = self.origin.absolute()
    print orig, abs
    zipfile = abs.replace(orig, "")[1:]
    return zipfile


  def vopen(self, node):
    print node.absolute()
    try:
      zipfile = self.nodeToZipFile(node)
      if zipfile in self.mapped_files.keys():
      #zipfile = node.
        buff = self.mapped_files[zipfile]
      else:
        buff = self.mappedFile(zipfile)
        if len(buff) > 0:
          self.mapped_files[zipfile] = buff
          fi = fdinfo()
          fi.thisown = False
          fi.node = node
          fi.offset = 0
          fd = self.fdm.push(fi)
      return fd
    except KeyError:
      formatted_lines = traceback.format_exc().splitlines()
      e = vfsError("[unzip::vopen] --> file not found\n" + formatted_lines[-1])
      e.thisown = False
      raise e


  def vread(self, fd, buff, size):
    print "fd", fd
    try:
      fi = self.fdm.get(fd)
      print fi.offset
      print fi.node.absolute()
      zipfile = self.nodeToZipFile(fi.node)      
      return fd
    except vfsError:
      formatted_lines = traceback.format_exc().splitlines()
      raise vfsError("[unzip::vopen] --> file not found\n" + formatted_lines[-1])

  def vseek(self, fd, offset, whence):
    pass


  def vclose(self, fd):
    pass


class unzip(Module):
  """Decompress zip file and create their content in virtual memory through module SHM.
This version of unzip store all data in RAM so don't decompress huge file."""
  def __init__(self):
    Module.__init__(self, "unzip", UNZIP)
    self.conf.add('file', 'node', False, "File to decompress.")
    self.conf.add_const('mime-type', 'Zip')
    self.tags = "archive"
