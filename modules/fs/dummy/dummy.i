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