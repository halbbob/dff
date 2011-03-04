/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
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
 */

%module(package="api.index") libindex

%include "std_string.i"
#ifndef WIN32
%include "stdint.i"
#else
%include "wstdint.i"
#endif
%include "std_list.i"
%include "std_map.i"
%include "windows.i"
%include "std_except.i"

%{
#include "../include/export.hpp"
#include "../include/index.hpp"
%}

%include "../include/export.hpp"
%include "../include/index.hpp"
