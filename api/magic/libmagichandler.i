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

%module(package="api.magichandler", directors="1") libmagichandler

#ifndef WIN32
%include "stdint.i"
#else
%include "wstdint.i"
#endif
%include "std_string.i"
%include "std_list.i"
%include "std_map.i"
%include "windows.i"

%{
#include "export.hpp"
#include "datatype.hpp"
#include "magichandler.hpp"
%}

%include "../include/export.hpp"
%import "../datatype/libdatatype.i"
%include "../include/magichandler.hpp"

%pythoncode
%{
  import sys
  import os

  try:
     MagicType = MagicHandler.Get()
     MimeType = MimeHandler.Get()
     if os.name == "nt":
        MagicType.setMagicFile(sys.path[0] + "/api/magic/magic.mgc")
        MimeType.setMagicFile(sys.path[0] + "/api/magic/magic.mgc")
     else:
        MagicType.setMagicFile("")
        MimeType.setMagicFile("")

  except RuntimeError:
     print "Unable to load magic. data types functionnalies won't work"
%}
