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
 *  Frederic B. <fba@digital-forensic.org>
 */

%module CARVER

%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "windows.i"

%{
#include "variant.hpp"
#include "vtime.hpp"
#include "fso.hpp"
#include "mfso.hpp"
#include "node.hpp"
#include "vlink.hpp"
#include "vfile.hpp"
#include "carver.hpp"
#include "common.hpp"
#include "../../../api/search/pattern.hpp"
%}


%import "../../../api/vfs/libvfs.i"


%typemap(in) unsigned char *
{
if (!PyString_Check($input)) 
   {
      	 PyErr_SetString(PyExc_ValueError,"Expected a string");
   	 return NULL;
   }
else
   {
	$1 = (unsigned char*)PyString_AsString($input);
   }
}

%typemap(in) unsigned char
{
if (!PyString_Check($input))
   {
      	 PyErr_SetString(PyExc_ValueError,"Expected a string");
   	 return NULL;
   }
else
   {
	if (PyString_Size($input) == 1)
	   {
		$1 = (unsigned char)PyString_AsString($input)[0];
   	   }
	else
	  {
		$1 = (unsigned char)PyString_AsString($input)[0];
	  }
   }
}


%include "carver.hpp"
%include "common.hpp"
%include "../../../api/search/pattern.hpp"

namespace std
{
  %template(listDescr)     list<description*>;
};
