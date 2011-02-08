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
 *  Solal J. <sja@digital-forensic.org>
 */

%module  LOCAL
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "windows.i"

%import "../../../api/vfs/libvfs.i"

%{
#include "fso.hpp"
#include "mfso.hpp"
#include "node.hpp"
#include "vlink.hpp"
#include "vfile.hpp"
#include "local.hpp"
%}

%include "local.hpp"


%pythoncode
%{
from api.module.module import *
from api.types.libtypes import *
class LOCAL(Module):
  """Add file from your operating system to the VFS"""
  def __init__(self):
    Module.__init__(self, 'local', local)
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Node, 
	                   "name": "parent", 
	                   "description": "files or folders will be added as child(ren) of this node or as the root node by default",
                           "parameters": {"type": Parameter.Customizable,
	                                  "predefined": ["/", "/local evidences"]}
                          })
    self.conf.addArgument({"input": Argument.Required|Argument.List|typeId.Path, 
	                   "name": "path", 
	                   "description": "Path to the file or directory on your operating system."})

    #self.conf.addArgument({"input": Argument.Required|Argument.List|typeId.Path, 
    #	                   "name": "path",
    #	  "description": "Path to the file or directory on your operating system.",
    #	  "parameters": {"type": Parameter.Fixed}})


  # self.conf.add("size", "uint64", True, "Force size of the file.")
    self.tags = "Connectors"
%}
