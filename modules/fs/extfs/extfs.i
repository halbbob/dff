/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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

%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "windows.i"

%{
#include "variant.hpp"
#include "vtime.hpp"
#include "mfso.hpp"
#include "node.hpp"
#include "vfile.hpp"
#include "vlink.hpp"
#include "extfs.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "extfs.hpp"

/*
namespace std
{
}; */

%pythoncode
%{

__dff_module_extfs_version__ = "1.0.0"

from api.module.module import *
from api.types.libtypes import Argument, typeId, Parameter

class EXTFS(Module):
  """ This module parses extented file system and try to recover deleted data."""
  def __init__(self):

    Module.__init__(self, 'extfs', Extfs)

    self.conf.addArgument({"name": "file",
                           "description": "file containing an EXT file system",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "blockpointers",
                           "description": "Add block pointer as extfs extended attributes",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "ils",
                           "description": "List inodes",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "blk",
                           "description": "Block allocation status",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "fsstat",
                           "description": "File system statistic",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "istat",
                           "description": "Inode statistics",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "jstat",
                           "description": "journal statistics",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "SB_check",
                           "description": "check superblock validity",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "i_orphans",
                           "description": "Parse orphan inodes",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "root_inode",
	                   "description": "Root inode number",
                           "input": Argument.Optional|Argument.Single|typeId.UInt64,
                           "parameters": {"type": Parameter.Editable,
                                          "predefined": [2]}
                           })
    self.conf.addArgument({"name": "SB_addr",
                           "description": "Super block address specified manualy",
                           "input": Argument.Optional|Argument.Single|typeId.UInt64,
                           "parameters": {"type": Parameter.Editable,
                                          "predefined": [1024]}
                           })
    self.conf.addConstant({"name": "mime-type", 
                           "type": typeId.String,
                           "description": "managed mime type",
	                   "values": ["ext2", "ext3", "ext4"]})
    self.tags = "File systems"
%}
