/* 
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
 * 
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 * 
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Christophe Malinge <cma@digital-forensic.org>
 *
 */

%module  NTFS 
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "windows.i"

%include "../../../api/exceptions/libexceptions.i"
%import "../../../api/vfs/libvfs.i"

%{

#include "ntfs.hpp"
%}
%include "ntfs.hpp"

/*
namespace std
{
}; */

%pythoncode
%{
from api.module.module import *
class NTFS(Module):
  def __init__(self):
    Module.__init__(self, 'ntfs', Ntfs)
    self.conf.add("parent", "node", False, "File to search NTFS file system in")
    self.conf.add("mftdecode", "int", True, "Only try to decode mft at this offset")
    self.conf.add("indexdecode", "int", True, "Only try to decode index records at this offset")
    self.conf.add_const("mime-type", "x86 boot sector")
    self.conf.description = "Creates a tree from a NTFS file system, for regular and deleted/orphan files.\nIt also provides human-readable dump of MFT or Indexex entries."
    self.tags = "file system"
%}
