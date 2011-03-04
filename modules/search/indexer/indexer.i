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

%module  INDEXER
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


%{
#include "variant.hpp"
#include "vtime.hpp"
#include "mfso.hpp"
#include "node.hpp"
#include "vfile.hpp"
#include "vlink.hpp"
#include "index.hpp"
#include "indexer.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "indexer.hpp"

/*
namespace std
{
}; */

%pythoncode
%{
from api.module.module import *
from api.types.libtypes import Argument, typeId, Variant, Parameter

class INDEXER(Module):
  """This module is a dff module."""
  def __init__(self):
    Module.__init__(self, 'indexer', Indexer)
    self.conf.addArgument({"name": "node",
                           "description": "dir to index",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "ils",
                           "description": "List inodes",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.tags = "Search"
%}
