/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
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

%module(package="api.exceptions", directors="1") libexceptions


%{
#include "exceptions.hpp"
%}

%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "std_except.i"
#ifndef WIN32
%include "stdint.i"
#else
%include "wstdint.i"
#endif
%include "windows.i"


%exception start
{
  try
    {
      SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
      SWIG_PYTHON_THREAD_END_ALLOW;
    }
  catch (vfsError &e)
    {
      SWIG_exception(SWIG_IOError, e.error.c_str());
    }
  catch (envError &e)
    {
      SWIG_exception(SWIG_AttributeError, e.error.c_str());
    }
  catch (Swig::DirectorException e)
    {
      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
      SWIG_fail;
      SWIG_PYTHON_THREAD_END_BLOCK;
    }
}

%exception
{
  try
    {
      //SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action;
      //SWIG_PYTHON_THREAD_END_ALLOW;
    }
  catch (Swig::DirectorException e)
    {
      SWIG_fail;
    }
  catch (vfsError &e)
    {
      SWIG_exception(SWIG_IOError, e.error.c_str());
    }
  catch (envError &e)
    {
      SWIG_exception(SWIG_AttributeError, e.error.c_str());
    }
  catch (const std::exception &e)
    {
      SWIG_exception(SWIG_RuntimeError, e.what());
    }
}


%include "../include/export.hpp"
%include "../include/exceptions.hpp"
