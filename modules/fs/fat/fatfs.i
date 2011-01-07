/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

%module  FATFS

%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "windows.i"

%import "../../../api/vfs/libvfs.i"

%{
#include "fatfs.hpp"
%}

%include "fatfs.hpp"

%pythoncode
%{
from api.module.module import *
class FATFS(Module):
  """This module create the tree contained in a fat file system, for normal and deleted files."""
  def __init__(self):
    Module.__init__(self, 'fatfs', Fatfs)
    self.conf.add("parent", "node", False, "Node containing a FAT file system")
    self.conf.add("carve_unallocated_clusters", "bool", True, "carve directories entries in unallocated clusters (more accurate but slower)")
    self.conf.add_const("mime-type", "x86 boot sector")
    self.tags = "File systems"
%}

