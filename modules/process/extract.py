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

import os
from api.vfs import *
from api.module.script import *
from api.exceptions.libexceptions import *
from api.module.module import *
import time
import traceback

class EXTRACT(Script):
  def __init__(self):
    Script.__init__(self, "extract")
    self.vfs = vfs.vfs()


  def start(self, args):
    nodes = args.get_lnode('files')
    path = args.get_path('syspath').path
    if path[-1] != "/":
      path += "/"
    recursive = args.get_bool('recursive')
    #for node in self.nodes:
    #  if node.isFile():
    #    self.total += 1
    #  if self.rec and self.hasChildren():
    #    self.total += self.totalFiles(node.children())
    #for node in self.nodes:
    #  self.launch(node)
    self.extractNodes(nodes, path, recursive)
    self.createReport()


  def initContext(self, nodes, path, recursive):
    self.path = path
    self.recursive = recursive
    self.total_files = 0
    self.total_folders = 0
    self.extracted_files = 0
    self.extracted_folders = 0
    self.files_errors = 0
    self.folders_errors = 0
    self.ommited_files = 0
    self.ommited_folders = 0
    self.log = {"files": {"ok": "", "nok": ""},
                "folders": {"ok": "", "nok": ""}} 
    self.extractedItemsCount(nodes)


  def createReport(self):
    stats = ""
    if self.total_files > 0:
      percent = (float(self.extracted_files) * 100) / self.total_files
      stats += "extracted file(s):   " + str(self.extracted_files) + "/" + str(self.total_files) + " (" + str(round(percent, 2)) + "%)\n"
      #self.res.add_const("file(s) extracted successfully", "\n" + self.log["files"]["ok"])

    if self.total_folders > 0:
      percent = (float(self.extracted_folders) * 100) / self.total_folders
      stats += "extracted folder(s): " + str(self.extracted_folders) + "/" + str(self.total_folders) + " (" + str(round(percent, 2)) + "%)\n" 
      #self.res.add_const("folder(s) extracted successfully", "\n" + self.log["folders"]["ok"])

    if self.ommited_files > 0:
      percent = (float(self.ommited_files) * 100) / self.total_files
      stats += "ommited file(s):     " + str(self.ommited_files) + "/" + str(self.total_files) + " (" + str(round(percent, 2)) + "%)\n"

    if self.ommited_folders > 0:
      percent = (float(self.ommited_folders) * 100) / self.total_folders
      stats += "ommited folder(s):   " + str(self.ommited_folders) + "/" + str(self.total_folders) + " (" + str(round(percent, 2)) + "%)\n"

    if self.files_errors > 0:
      percent = (float(self.files_errors) * 100) / self.total_files
      stats += "file(s) error:       " + str(self.files_errors) + "/" + str(self.total_files) + " (" + str(round(percent, 2)) + "%)\n"
      self.res.add_const("file(s) errors", "\n" + self.log["files"]["nok"])

    if self.folders_errors > 0:
      percent = (float(self.folders_errors) * 100) / self.total_folders
      stats += "folder(s) error:     " + str(self.folders_errors) + "/" + str(self.total_folders) + " (" + str(round(percent, 2)) + "%)\n"
      self.res.add_const("folder(s) errors", "\n" + self.log["folders"]["nok"])

    if len(stats):
      self.res.add_const("statistics", "\n" + stats)


  def extractNodes(self, nodes, path, recursive):
    self.initContext(nodes, path, recursive)
    for node in nodes:
      syspath = self.path + node.name()
      if not self.recursive:
        if node.isFile():
          self.extractFile(node, syspath)
        elif node.hasChildren():
          self.makeFolder(node, syspath)
      else:
        if node.isFile():
          if node.hasChildren():
            self.extractFile(node, syspath + ".bin")
            self.makeFolder(node, syspath)
            self.recurse(node.children(), node.name() + "/")
          else:
            self.extractFile(node, syspath)
        if node.hasChildren():
          self.makeFolder(node, syspath)
          self.recurse(node.children(), node.name() + "/")


  def extractedItemsCount(self, nodes):
    for node in nodes:
      if node.isFile():
        self.total_files += 1
        if node.hasChildren() and self.recursive:
          self.total_folders += 1
          self.extractedItemsCount(node.children())
      if node.hasChildren():
        self.total_folders += 1
        if node.hasChildren() and self.recursive:
          self.extractedItemsCount(node.children())


  def recurse(self, nodes, vpath):
    recnodes = []
    for node in nodes:
      syspath = self.path + vpath + node.name()
      if node.isFile():
        if node.hasChildren():
          self.extractFile(node, syspath + ".bin")
          if self.makeFolder(node, syspath):
            recnodes.append(node)
        else:
          self.extractFile(node, syspath)
      if node.hasChildren():
        if self.makeFolder(node, syspath):
          recnodes.append(node)

    for recnode in recnodes:
      self.recurse(recnode.children(), vpath + recnode.name() + "/")


  def updateStateInfo(self):
    buff = ""
    if self.total_files > 0:
      percent = (float(self.extracted_files) * 100) / self.total_files
      buff += "extracted file(s):   " + str(self.extracted_files) + "/" + str(self.total_files) + " (" + str(round(percent, 2)) + "%)\n"
    if self.total_folders > 0:
      percent = (float(self.extracted_folders) * 100) / self.total_folders
      buff += "extracted folder(s): " + str(self.extracted_folders) + "/" + str(self.total_folders) + " (" + str(round(percent, 2)) + "%)\n"
    if self.files_errors > 0:
      percent = (float(self.files_errors) * 100) / self.total_files
      buff += "file(s) error:       " + str(self.files_errors) + "/" + str(self.total_files) + " (" + str(round(percent, 2)) + "%)\n"
    if self.folders_errors > 0:
      percent = (float(self.folders_errors) * 100) / self.total_folders
      buff += "folder(s) error:     " + str(self.folders_errors) + "/" + str(self.total_folders) + " (" + str(round(percent, 2)) + "%)\n"
    if self.ommited_files > 0:
      percent = (float(self.ommited_files) * 100) / self.total_files
      buff += "ommited file(s):     " + str(self.ommited_files) + "/" + str(self.total_files) + " (" + str(round(percent, 2)) + "%)\n"
    if self.ommited_folders > 0:
      percent = (float(self.ommited_folders) * 100) / self.total_folders
      buff += "ommited folder(s):   " + str(self.ommited_folders) + "/" + str(self.total_folders) + " (" + str(round(percent, 2)) + "%)\n"
    self.stateinfo = buff


  def countOmmited(self, nodes):
    for node in nodes:
      if node.isFile():
        self.ommited_files += 1
        if node.hasChildren() and self.recursive:
          self.ommited_folders += 1
          self.countOmmited(node.children())
      if node.hasChildren():
        self.ommited_folders += 1
        if node.hasChildren() and self.recursive:
          self.countOmmited(node.children())      


  def makeFolder(self, node, syspath):
    ret = True
    if not os.path.exists(syspath):
      try:
        os.mkdir(syspath)
        self.log["folders"]["ok"] += syspath + "\n"
        self.extracted_folders += 1
      except OSError:
        self.folders_errors += 1
        formatted_lines = traceback.format_exc().splitlines()
        self.log["folders"]["nok"] += formatted_lines[-1] + "\n"
        self.countOmmited(node.children())
        ret = False
    else:
      self.log["folders"]["ok"] += syspath + "\n"
      self.extracted_folders += 1
    self.updateStateInfo()
    return ret


  def extractFile(self, node, syspath):
    self.updateStateInfo()
    try:
      vfile = node.open()
      sysfile = open(syspath, 'wb')
      readsize = 8192
      buff = vfile.read(readsize)
      while len(buff):
        sysfile.write(buff)
        buff = vfile.read(readsize)
      vfile.close()
      sysfile.close()
      self.log["files"]["ok"] += node.absolute() + " --> " + syspath + "\n"
      self.extracted_files += 1
    except (vfsError, OSError, IOError):
      self.files_errors += 1
      formatted_lines = traceback.format_exc().splitlines()
      self.log["files"]["nok"] += formatted_lines[-1] + "\n"
    self.updateStateInfo()


class extract(Module):
  """Extract file in your operating system file system."""
  def __init__(self):
    Module.__init__(self, "extract", EXTRACT)
    self.conf.add("files", "lnode", False, "Files or directories list to extract.")
    self.conf.add("syspath", "path", False, "Local file system path where to extract files.") 
    self.conf.add("recursive", "bool", True, "Extract recursivly each files in all in sub-directories.")
    self.tags = "Node"
