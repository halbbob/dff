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
 *  Solal J. <sja@digital-forensic.org>
 */

%module(package="api.datatype", directors="1") libdatatype

%feature("director") DataTypeHandler;

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
%}
%include "../include/export.hpp"
%include "../include/datatype.hpp"

namespace std
{
  %template(ListDataType)       list<DataTypeHandler*>;
  %template(MapDataType)        map<std::string, uint32_t>;
}
