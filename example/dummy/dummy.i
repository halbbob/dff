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

%module  DUMMY
 
// You will here need to add every headers you need
%include "std_string.i"
%include "windows.i"
%import "../../../api/vfs/libvfs.i"

%{
#include "dummy.hpp"
%}

%include "dummy.hpp"

namespace std
{
  %template(ListString)         list<string>;
};

%pythoncode
%{
from api.module.module import *
class DUMMY(Module):
 """Useless DUMMY module example"""
 def __init__(self):
   Module.__init__(self, 'dummy', Dummy)
   self.conf.add("parent", "node", True, "The file will be added as son of this node or as the root node by default.")
   self.tags = "file system"
%}
