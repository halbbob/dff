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
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

%module  EXTFS
#ifndef WIN32
%include "stdint.i"
#else
%include "wstdint.i"
#endif
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "windows.i"

%import "../../../api/vfs/libvfs.i"

%{

#include "extfs.hpp"
%}
%include "extfs.hpp"

/*
namespace std
{
}; */

%pythoncode
%{
from api.module.module import *
class EXTFS(Module):
  """ This module parses extented file system and try to recover deleted data."""
  def __init__(self):

    Module.__init__(self, 'extfs', Extfs)
    self.conf.add("parent", "node", False, "The file will be added as son.")

    self.conf.add("run", "bool", True, "Running the driver")
    self.conf.add("ils", "string", True, "List inodes")
    self.conf.add("blk", "string", True, "Block allocation status")
    self.conf.add("SB_check", "bool", True, "check superblock validity")
    self.conf.add("fsstat", "bool", True, "File system statistic.")
    self.conf.add("istat", "string", True, "Inode statistics")
    self.conf.add("jstat", "string", True, "journal statistics")
    self.conf.add("i_orphans", "string", True, "Parse orphan inodes")
#    self.conf.add("dir_ls", "string", True, "directory content")
    self.conf.add("SB_addr", "string", True, "Super block address specified manualy")
    self.conf.add("root_inode", "string", True, "Root inode number")
#    self.conf.add("check_alloc", "string", True, "Checking file system consistency")

    self.conf.add_const("mime-type", "ext2")
    self.conf.add_const("mime-type", "ext3")
    self.conf.add_const("mime-type", "ext4")
    self.conf.add_const("run", True)
    self.tags = "File systems"
%}
