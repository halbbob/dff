/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

%module PARTITION
%include "std_list.i"
%include "std_map.i"
%include "windows.i"


%{
#include "variant.hpp"
#include "vtime.hpp"
#include "export.hpp"
#include "partition.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "partition.hpp"


%pythoncode
%{
from api.module.module import *
from api.types.libtypes import Argument, typeId

class PARTITION(Module):
  """Create partition table found in the underlaying file"""
  def __init__(self):
    Module.__init__(self, 'partition', Partition)
    self.conf.addArgument({"name": "file",
                           "description": "file containing one or more partition(s)",
	                   "input": Argument.Required|Argument.Single|typeId.Node})    
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["partition"]})
    self.tags = "Volumes"
%}
