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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

%module(package="api.types") libtypes
%feature("autodoc", 1); //1 = generate type for func proto, no work for typemap
%feature("docstring");

#ifndef WIN32
%include "stdint.i"
#else
%include "wstdint.i"
#endif
%include "std_string.i"
%include "std_list.i"
%include "std_map.i"
%include "windows.i"
%include "std_except.i"

%import "../exceptions/libexceptions.i"

%{
#include <sys/stat.h>
#include <datetime.h>
#include "export.hpp"
#include "exceptions.hpp"

#include "variant.hpp"
#include "argument.hpp"
#include "config.hpp"
#include "path.hpp"
#include "vtime.hpp"
#include "Time.h"
  
#ifndef WIN32
#include <stdint.h>
#else
#include "wstdint.h"
#endif
%}

%inline %{
Variant*  pyObjectToVariant(PyObject* val, uint8_t t);
 %}

%include "../include/variant.hpp"
%include "../include/argument.hpp"
%include "../include/export.hpp"
%include "../include/config.hpp"
%include "../include/path.hpp"
%include "../include/Time.h"
%include "../include/vtime.hpp"

%inline %{

bool checkSignedOverflow (PyObject* val, uint8_t t)
{
   long long ll;
   PyObject* pyerr;
   
   if (PyInt_Check(val))
      {
	long l;

        SWIG_PYTHON_THREAD_BEGIN_BLOCK;
        l = PyInt_AsLong(val);
        pyerr = PyErr_Occurred();
        SWIG_PYTHON_THREAD_END_BLOCK;
	if ((l == -1) && (pyerr != NULL))
	   return false;
	else
	   ll = (long long)l;
      }
   else if (PyLong_Check(val))
      {
	long l;

        SWIG_PYTHON_THREAD_BEGIN_BLOCK;
        l = PyLong_AsLong(val);
        pyerr = PyErr_Occurred();
        SWIG_PYTHON_THREAD_END_BLOCK;
	if ((l == -1) && (pyerr != NULL))
	{
	   SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	   PyErr_Clear();
	   ll = PyLong_AsLongLong(val);
	   pyerr = PyErr_Occurred();
           SWIG_PYTHON_THREAD_END_BLOCK;
	   if ((ll == -1) && (pyerr != NULL))
	      return false;
   	}
	else
	   ll = (long long)l;
      }
   else
      return false;

   if ((t == typeId::Int16) && (ll >= INT16_MIN) && (ll <= INT16_MAX))
   {
     printf("%lld\n", ll);
      return true;
   }
   else if ((t == typeId::Int32) && (ll >= INT32_MIN) && (ll <= INT32_MAX))
   {
      printf("%lld\n", ll);
      return true;
   }
   else if ((t == typeId::Int64) && (ll >= INT32_MIN) && (ll <= INT64_MAX))
   {
      printf("%lld\n", ll);
      return true;
   }
   else
      return false;
}


Variant* pySignedNumericToVariant(PyObject* val, uint8_t t)
{
   long long ll;
   PyObject* pyerr;
   Variant* vval;
   
   if (PyInt_Check(val))
      {
	long l;

        SWIG_PYTHON_THREAD_BEGIN_BLOCK;
        l = PyInt_AsLong(val);
        pyerr = PyErr_Occurred();
        SWIG_PYTHON_THREAD_END_BLOCK;
	if ((l == -1) && (pyerr != NULL))
	   return NULL;
	else
	   ll = (long long)l;
      }
   else if (PyLong_Check(val))
      {
	long l;

        SWIG_PYTHON_THREAD_BEGIN_BLOCK;
        l = PyLong_AsLong(val);
        pyerr = PyErr_Occurred();
        SWIG_PYTHON_THREAD_END_BLOCK;
	if ((l == -1) && (pyerr != NULL))
	{
	   SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	   PyErr_Clear();
	   ll = PyLong_AsLongLong(val);
	   pyerr = PyErr_Occurred();
           SWIG_PYTHON_THREAD_END_BLOCK;
	   if ((ll == -1) && (pyerr != NULL))
	      return NULL;
   	}
	else
	   ll = (long long)l;
      }
   else
      return NULL;

   if ((t == typeId::Int16) && (ll >= INT16_MIN) && (ll <= INT16_MAX))
   {
      int16_t   v;
      v = static_cast<int16_t>(ll);
      vval = new Variant(v);
      return vval;
   }
   else if ((t == typeId::Int32) && (ll >= INT32_MIN) && (ll <= INT32_MAX))
   {
      int32_t   v;
      v = static_cast<int32_t>(ll);
      vval = new Variant(v);
      return vval;
   }
   else if ((t == typeId::Int64) && (ll >= INT32_MIN) && (ll <= INT64_MAX))
   {
      int64_t   v;
      v = static_cast<int64_t>(ll);
      vval = new Variant(v);
      return vval;
   }
   else
      return NULL;
}


bool checkUnsignedOverflow (PyObject* val, uint8_t t)
{
   unsigned long long ull;
   PyObject* pyerr;
   
   if (PyInt_Check(val))
      {
        long l;

        SWIG_PYTHON_THREAD_BEGIN_BLOCK;
        l = PyInt_AsLong(val);
        pyerr = PyErr_Occurred();
        SWIG_PYTHON_THREAD_END_BLOCK;
	if ((l < 0) && (pyerr != NULL))
	   return false;
	else
           ull = (unsigned long long)l;
      }
   else if (PyLong_Check(val))
      {
	unsigned long ul;

        SWIG_PYTHON_THREAD_BEGIN_BLOCK;
        ul = PyLong_AsUnsignedLong(val);
        pyerr = PyErr_Occurred();
        SWIG_PYTHON_THREAD_END_BLOCK;
	if (pyerr != NULL)
	{
           SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	   PyErr_Clear();
	   ull = PyLong_AsUnsignedLongLong(val);
           pyerr = PyErr_Occurred();
           SWIG_PYTHON_THREAD_END_BLOCK;
	   if (pyerr != NULL)
	     return false;
	}
	else
	  ull = (unsigned long long)ul;
      }
   else
      return false;

   if ((t == typeId::UInt16) && (ull <= UINT16_MAX))
   {
      printf("%llu\n", ull);
      return true;
   }
   else if ((t == typeId::UInt32) && (ull <= UINT32_MAX))
   {
      printf("%llu\n", ull);
      return true;
   }
   else if ((t == typeId::UInt64) && (ull <= UINT64_MAX))
   {
      printf("%llu\n", ull);
      return true;
   }
   else
      return false;
}

Variant* pyUnsignedNumericToVariant(PyObject* val, uint8_t t)
{
   unsigned long long ull;
   PyObject* pyerr;
   Variant* vval;
   
   if (PyInt_Check(val))
      {
        long l;

        SWIG_PYTHON_THREAD_BEGIN_BLOCK;
        l = PyInt_AsLong(val);
        pyerr = PyErr_Occurred();
        SWIG_PYTHON_THREAD_END_BLOCK;
	if ((l < 0) && (pyerr != NULL))
	   return NULL;
	else
           ull = (unsigned long long)l;
      }
   else if (PyLong_Check(val))
      {
	unsigned long ul;

        SWIG_PYTHON_THREAD_BEGIN_BLOCK;
        ul = PyLong_AsUnsignedLong(val);
        pyerr = PyErr_Occurred();
        SWIG_PYTHON_THREAD_END_BLOCK;
	if (pyerr != NULL)
	{
           SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	   PyErr_Clear();
	   ull = PyLong_AsUnsignedLongLong(val);
           pyerr = PyErr_Occurred();
           SWIG_PYTHON_THREAD_END_BLOCK;
	   if (pyerr != NULL)
	     return NULL;
	}
	else
	  ull = (unsigned long long)ul;
      }
   else
      return NULL;

   if ((t == typeId::UInt16) && (ull <= UINT16_MAX))
   {
	uint16_t v;
	v = static_cast<uint16_t>(ull);
	vval = new Variant(v);
	return vval;
   }
   else if ((t == typeId::UInt32) && (ull <= UINT32_MAX))
   {
	uint32_t v;
	v = static_cast<uint32_t>(ull);
	vval = new Variant(v);
	return vval;
   }
   else if ((t == typeId::UInt64) && (ull <= UINT64_MAX))
   {
	uint64_t v;
	v = static_cast<uint64_t>(ull);
	vval = new Variant(v);
	return vval;
   }
   else
      return NULL;
}

bool checkStringOverflow (PyObject* val, uint8_t t)
{
     return true;
}


Variant* pyObjectToInt16Variant(PyObject* val)
{
   Variant*     var;
   long         l;
   int16_t	i16;

   l = PyInt_AsLong(val);
   i16 = static_cast<int16_t>(l);
   var = new Variant(i16);
   return var;
}


Variant* pyObjectToInt32Variant(PyObject* val)
{
   Variant*     var;
   long         l;
   int32_t	i32;

   l = PyInt_AsLong(val); 
   i32 = static_cast<int32_t>(l);
   var = new Variant(i32);
   return var;
}


Variant* pyObjectToInt64Variant(PyObject* val)
{
   Variant*     var;
   long         l;
   int64_t	i64;

   l = PyInt_AsLong(val); 
   i64 = static_cast<int64_t>(l);
   var = new Variant(i64);
   return var;
}


Variant* pyObjectToUInt16Variant(PyObject* val)
{
   Variant*     var;
   long         l;
   uint16_t	ui16;

   l = PyInt_AsLong(val);
   ui16 = static_cast<uint16_t>(l);
   var = new Variant(ui16);
   return var;
}


Variant* pyObjectToUInt32Variant(PyObject* val)
{
   Variant*     var;
   long         l;
   uint32_t	ui32;

   l = PyInt_AsLong(val); 
   ui32 = static_cast<uint32_t>(l);
   var = new Variant(ui32);
   return var;
}

Variant* pyObjectToUInt64Variant(PyObject* val)
{
   Variant*     var;
   long         l;
   uint64_t	ui64;

   l = PyInt_AsLong(val); 
   ui64 = static_cast<uint64_t>(l);
   var = new Variant(ui64);
   return var;
}



Variant* intToVariant(PyObject* val, uint8_t t)
{
   Variant* var;
   long vval;

   vval = PyInt_AsLong(val);
}

Variant*  pyStringToVariant(PyObject* val, uint8_t t)
{
   Py_ssize_t size;
   char* str;
   Variant* vval;

   if (PyString_Check(val))
   {
      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
      size = PyString_Size(val);
      str = PyString_AsString(val);
      SWIG_PYTHON_THREAD_END_BLOCK;
      if (size < 0)
      	 return NULL;
      else if (t == typeId::Char)
      {
	char c;
        if (size < 2)
	{
	   c = *str;
	   vval = new Variant(c);
	   return vval;
	}
      }
      else if (t == typeId::String)
      {
	std::string  s;
	s = std::string(str);
	vval = new Variant(s);
	return vval;
      }
      else if (t == typeId::CArray)
      {
	vval = new Variant(str);
	return vval;	
      }
   }
   else
     return NULL;
}

Variant* pyListToVariant(PyObject* val, uint8_t t)
{
  Py_ssize_t size;
  PyObject* item;
  Variant* vval;
  std::list<Variant *>  vlist;
  Py_ssize_t i;
  bool	     err;

  size = PyList_Size(val);
  i = 0;
  err = false;
  while ((i != size) && (err != true))
    {
       item = PyList_GetItem(val, i);
       if ((PyList_Check(item)) || (PyDict_Check(item)))
       	  err = true;
       else
       {
          vval = pyObjectToVariant(item, t);
          if (vval != NULL)
       	     vlist.push_back(vval);
          else
	    err = true;
       }
       i++;
    }
  if (!err)
  {
    //printf("No error in vlist creation\n");
     Variant* res = new Variant(vlist);
     return res;
  }
  else
  {
     printf("Error while generating vlist !! Wrong type provided\n");
     vlist.erase(vlist.begin(), vlist.end());
     return NULL;
  }
}

Variant*  pyObjectToVariant(PyObject* val, uint8_t t)
{
   if (PyList_Check(val))
     return pyListToVariant(val, t);
   else if ((t == typeId::Int16) || (t == typeId::Int32) || (t == typeId::Int64))
     return pySignedNumericToVariant(val, t);
   else if ((t == typeId::UInt16) || (t == typeId::UInt32) || (t == typeId::UInt64))
     return pyUnsignedNumericToVariant(val, t);
   else if ((t == typeId::String) || (t == typeId::Char) || (t == typeId::CArray))
     return pyStringToVariant(val, t);
   else
     return NULL;
}

bool isTypeCompatible(PyObject* val, uint8_t t)
{
   if ((t == typeId::Int16) || (t == typeId::Int32) || (t == typeId::Int64))
	return checkSignedOverflow(val, t);
   if ((t == typeId::UInt16) || (t == typeId::UInt32) || (t == typeId::UInt64))
        return checkUnsignedOverflow(val, t);
   if ((t == typeId::String) || (t == typeId::Char) || (t == typeId::CArray))
        return checkStringOverflow(val, t);
    if (t == typeId::Node)
       {
    	  return false;
       }
    if (t == typeId::Path)
      {
         return true;
      }
    return false;
}

bool validatePyList(PyObject* val, uint8_t t)
{
  Py_ssize_t size;
  PyObject* item;
  Py_ssize_t i;

  size = PyList_Size(val);
  for (i = 0; i != size; i++)
    {
       item = PyList_GetItem(val, i);
       if (!isTypeCompatible(item, t))
         {
	   SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	   PyErr_SetString(PyExc_TypeError, "Config::add_const, list contains not compatible argument");
	   SWIG_PYTHON_THREAD_END_BLOCK;
	   return false;
	 }
     }
  return true;
}


bool validateDefault (PyObject* val, uint8_t t)
{ 
  if (PyList_Check(val))
     {
        return validatePyList(val, t);
     }
  else
     {
       if (!isTypeCompatible(val, t))
	 {
	   SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	   PyErr_SetString(PyExc_KeyError, "Config::add_const argument is not compatible");
	   SWIG_PYTHON_THREAD_END_BLOCK;
	   return false;
	 }
     }
  return true;
}

/* PyObject*	start(PyObject* input) */
/* { */
/*   PyObject*	resultobj = 0; */
/*   //Variant*	params; */
/*   //uint8_t	type; */
  
/*   if (!PyDict_Check(input)) */
/*     { */
/*       SWIG_PYTHON_THREAD_BEGIN_BLOCK; */
/*       PyErr_SetString(PyExc_TypeError, "fso::start argument 1 must be of DictType"); */
/*       SWIG_PYTHON_THREAD_END_BLOCK; */
/*       return NULL; */
/*     } */
/*   else */
/*     { */
/*       PyObject *key, *value; */
/*       Py_ssize_t pos = 0; */
/*       std::map<std::string, Variant* > cppmap; */
      
/*       while (PyDict_Next(input, &pos, &key, &value)) */
/* 	{ */
/* 	  if (!PyString_Check(key)) */
/* 	    { */
/* 	      SWIG_PYTHON_THREAD_BEGIN_BLOCK; */
/* 	      PyErr_SetString(PyExc_TypeError, "fso::start --> dict keys must be of type string"); */
/* 	      SWIG_PYTHON_THREAD_END_BLOCK; */
/* 	      return NULL; */
/* 	    } */
/* 	  else */
/* 	    { */
/* 	      SWIG_PYTHON_THREAD_BEGIN_BLOCK; */
/* 	      char* cstr = PyString_AsString(key); */
/* 	      SWIG_PYTHON_THREAD_END_BLOCK; */
/* 	      if (cstr != NULL) */
/* 		{ */
/* 		  Variant* vval; */
		  
/* 		  if ((vval = pyObjectToVariant(value, 1)) != NULL) */
/* 		    cppmap[std::string(cstr)] = vval; */
/* 		  else */
/* 		    return NULL; */
/* 		} */
/* 	    } */
/* 	  resultobj = SWIG_Py_Void(); */
/* 	  return resultobj; */
/* 	} */
/*     } */
/* } */

%}


%pythoncode
%{
  import traceback
  import types


  Variant.__origininit__ = Variant.__init__
  Variant.__init__ = Variant.__proxyinit__
  Variant.funcMapper = {typeId.Char: "_Variant__Char",
                          typeId.Int16: "_Variant__Int16",
                          typeId.UInt16: "_Variant__UInt16",
                          typeId.Int32: "_Variant__Int32",
                          typeId.UInt32: "_Variant__UInt32",
                          typeId.Int64: "_Variant__Int64",
                          typeId.UInt64: "_Variant__UInt64",
                          typeId.String: "_Variant__String",
                          typeId.CArray: "_Variant__CArray",
			  typeId.Node: "_Variant__Node",
			  typeId.Path: "_Variant__Path",
                          typeId.VTime: "_Variant__VTime",
		          typeId.List: "_Variant__VList",
  		          typeId.Map: "_Variant__VMap"}

%}

%template(__Char) Variant::value<char>;
%template(__Int16) Variant::value<int16_t>;
%template(__UInt16) Variant::value<uint16_t>;
%template(__Int32) Variant::value<int32_t>;
%template(__UInt32) Variant::value<uint32_t>;
%template(__Int64) Variant::value<int64_t>;
%template(__UInt64) Variant::value<uint64_t>;
%template(__CArray) Variant::value<char *>;
%template(__Node) Variant::value<Node*>;
%template(__Path) Variant::value<Path*>;
%template(__VTime) Variant::value<vtime*>;

%template(__String) Variant::value<std::string>;
%template(VList) std::list<Variant*>;
%template(VMap) std::map<std::string, Variant*>;
%template(__VList) Variant::value< std::list<Variant *> >;
%template(__VMap) Variant::value< std::map<std::string, Variant *> >;



%extend Argument
{

  /* PyObject*	addPredefinedParameters(PyObject* val) */
  /* { */
  /*   PyObject*	resultobj = 0; */
  /*   Variant*	params; */
  /*   uint8_t	type; */

  /*   SWIG_PYTHON_THREAD_BEGIN_BLOCK; */
  /*   SWIG_PYTHON_THREAD_BEGIN_ALLOW; */
  /*   type = self->type(); */
  /*   SWIG_PYTHON_THREAD_END_ALLOW; */
  /*   SWIG_PYTHON_THREAD_END_BLOCK; */
  /*   params = pyObjectToVariant(val, type); */
  /*   if (params != NULL) */
  /*     { */
  /* 	SWIG_PYTHON_THREAD_BEGIN_BLOCK; */
  /* 	SWIG_PYTHON_THREAD_BEGIN_ALLOW; */
  /* 	self->addPredefinedParameters(params); */
  /* 	SWIG_PYTHON_THREAD_END_ALLOW; */
  /* 	SWIG_PYTHON_THREAD_END_BLOCK; */
  /* 	resultobj = SWIG_Py_Void(); */
  /* 	return resultobj; */
  /*     } */
  /*   else */
  /*     { */
  /* 	SWIG_PYTHON_THREAD_BEGIN_BLOCK; */
  /* 	PyErr_SetString(PyExc_ValueError, "Argument::setPredefinedParameters(), provided value is not compatbile with the type of argument\n"); */
  /* 	SWIG_PYTHON_THREAD_END_BLOCK; */
  /* 	return NULL; */
  /*     } */
  /*   /\* if (!PyString_Check(val)) *\/ */
  /*   /\*   { *\/ */
  /*   /\* 	SWIG_PYTHON_THREAD_BEGIN_BLOCK; *\/ */
  /*   /\* 	PyErr_SetString(PyExc_TypeError, "Config::add_const first argument must be a string"); *\/ */
  /*   /\* 	SWIG_PYTHON_THREAD_END_BLOCK; *\/ */
  /*   /\* 	return NULL; *\/ */
  /*   /\*   } *\/ */
  /*   /\* else *\/ */
  /*   /\*   { *\/ */
    
  /* 	//SWIG_PYTHON_THREAD_BEGIN_BLOCK; */
  /* 	//SWIG_PYTHON_THREAD_BEGIN_ALLOW; */
  /* 	//params = self->parameters(); */
  /* 	//SWIG_PYTHON_THREAD_END_ALLOW; */
  /* 	//SWIG_PYTHON_THREAD_END_BLOCK; */
  /* 	//if (it != params.end()) */
  /* 	//  { */
  /* 	//    param = (*it).second; */
  /* 	//    Variant* vval; */
  /* 	    //if (validateDefault(val, param->type())) */
  /* 	//    if ((vval = pyObjectToVariant(val, param->type())) != NULL) */
  /* 	//     { */
  /* 	//		param->addDefault(vval); */
  /* 	//		resultobj = SWIG_Py_Void(); */
  /* 	//		return resultobj; */
  /* 	//	      } */
  /* 	//	    else */
  /* 	//	      return NULL; */
  /* 	//  } */
  /* 	/\* else *\/ */
  /* 	/\*   { *\/ */
  /* 	/\*     SWIG_PYTHON_THREAD_BEGIN_BLOCK; *\/ */
  /* 	/\*     PyErr_SetString(PyExc_KeyError, "Config::__parameters map<std::string, Parameters * > requested name not found"); *\/ */
  /* 	/\*     SWIG_PYTHON_THREAD_END_BLOCK; *\/ */
  /* 	/\*     return NULL; *\/ */
  /* 	/\*   } *\/ */
  /* 	/\* resultobj = SWIG_Py_Void(); *\/ */
  /* 	/\* return resultobj; *\/ */
  /*   // } */
  /* } */

  PyObject*			activateParameters(PyObject* param)
  {
  }

  PyObject*			deactivateParameter(PyObject* param)
  {
  }
}

%rename(__eq__) Variant::operator==;

%extend Variant
{

  /* bool	operator==(PyObject* val) */
  /* { */
  /*   Variant*	v; */

  /*   PyTypeObject*	ob_type; */
  /*   if ((ob_type = val->ob_type) != NULL) */
  /*     { */
  /* 	printf("ob_type->tp_name: %s\n", ob_type->tp_name); */
  /* 	//if (ob_type->tp_name) */
  /* 	if (ob_type->tp_name != NULL) */
  /* 	  { */
  /* 	    if (strncmp("Variant", ob_type->tp_name, 7) == 0) */
  /* 	      { */
  /* 		void* argp1 = 0; */
  /* 		Variant *arg1 = (Variant *) 0 ; */
  /* 		int res1 = SWIG_ConvertPtr(val, &argp1, SWIGTYPE_p_Variant, 0 | 0); */
  /* 		if (SWIG_IsOK(res1)) */
  /* 		  { */
  /* 		    arg1 = reinterpret_cast< Variant * >(argp1); */
  /* 		    printf("Variant provided, subtype GetOriginalType: %d\n", arg1->type()); */
  /* 		    return self->operator==(arg1->value()); */
  /* 		  } */
  /* 	      } */
  /* 	    else if (strncmp("VList", ob_type->tp_name, 5) == 0) */
  /* 	      { */
  /* 		void* argp1 = 0; */
  /* 		std::list< Variant *> *arg1 = (std::list< Variant * > *) 0 ; */
  /* 		int res1 = SWIG_ConvertPtr(val, &argp1, SWIGTYPE_p_std__listT_Variant_p_std__allocatorT_Variant_p_t_t, 0 | 0); */
  /* 		if (SWIG_IsOK(res1)) */
  /* 		  { */
  /* 		    arg1 = reinterpret_cast< std::list<Variant * > * >(argp1); */
  /* 		    printf("VList provided\n"); */
  /* 		    return self->operator==(*arg1); */
  /* 		  } */
  /* 	      } */
  /* 	    else if (strncmp("VMap", ob_type->tp_name, 4) == 0) */
  /* 	      { */
  /* 		void* argp1 = 0; */
  /* 		std::map< std::string, Variant *> *arg1 = (std::map< std::string, Variant * > *) 0 ; */
  /* 		int res1 = SWIG_ConvertPtr(val, &argp1, SWIGTYPE_p_std__mapT_std__string_Variant_p_std__lessT_std__string_t_std__allocatorT_std__pairT_std__string_const_Variant_p_t_t_t, 0 | 0); */
  /* 		if (SWIG_IsOK(res1)) */
  /* 		  { */
  /* 		    arg1 = reinterpret_cast< std::map<std::string, Variant * > * >(argp1); */
  /* 		    printf("VMap provided\n"); */
  /* 		    return self->operator==(*arg1); */
  /* 		  } */
  /* 	      } */
  /* 	    else if ((v = pyObjectToVariant(val, self->type())) != NULL) */
  /* 	      { */
  /* 		return self->operator==(v); */
  /* 	      } */
  /* 	    else */
  /* 	      return false; */
  /* 	  } */
  /*     } */
  /*   else */
  /*     return false; */
  /* } */

  /* Variant(PyObject*) */
  /*   { */
  /*   } */
  %pythoncode
  %{
    def __proxyinit__(self, *args):
        if len(args) == 1:
           if type(args[0]) in [type(VList), type(VMap)]:
              args[0].thisown = False
        self.__origininit__(*args)

    def __repr__(self):
        #if self.type() in [typeId.Char, typeId.CArray, typeId.String]:
           #buff = "'" + str(self.value()) + "'"
        #else:
        buff = str(self.value())
        return buff

    def value(self):
        valType = self.type()
        if valType in self.funcMapper.keys():
            func = getattr(self, self.funcMapper[valType])
            if func != None:
                return func()
            else:
                return None
        else:
            return None
  %}
};

%pythoncode
%{
########################################################
# Following method provides overload for VMap and VList#
########################################################
VariantType = str(type(Variant()))[8:-2]
VListType = str(type(VList()))[8:-2]
VMapType = str(type(VMap()))[8:-2]

baseManagedTypes = [types.BooleanType, types.IntType, types.LongType,
                    types.StringType, types.FloatType]

def create_container_from_item(item):
    if str(type(item)).find(VariantType) != -1 or str(type(item)).find(VListType) != -1 or str(type(item)).find(VMapType) != -1:
        item.thisown = False
        return item
    elif type(item) == types.ListType:
        vl = VList()
        vl.thisown = False
        for i in item:
            container = create_container_from_item(i)
            container.thisown = False
            vl.append(container)
        return vl
    elif type(item) == types.DictType:
        vm = VMap()
        vm.thisown = False
        for key, val in item.iteritems():
            strkey = str(key)
            container = create_container_from_item(val)
            container.thisown = False
            VMap[strkey] = container
        return vm
    elif type(item) in baseManagedTypes:
        vitem = Variant(item)
        vitem.thisown = False
        return vitem
    else:
        TypeError("Management of type " + str(type(item)) + " is not implemented")


def create_variant_from_item(item):
    try:
        if str(type(item)).find(VariantType) != -1:
            return item
        else:
            vitem = create_container_from_item(item)
            if str(type(vitem)).find(VListType) != -1 or str(type(vitem)).find(VMapType) != -1:
                vvitem = Variant(vitem)
                vvitem.thisown = False
                return vvitem
            else:
                return vitem
    except(TypeError):
        traceback.print_exc()
        return None


# Wrapping methods for VList
def __vlist_proxyinit__(self, *args):
    self.__originit__()
    if len(args) >= 1:
        for arg in args:
            self.append(arg)

VList.__originit__ = VList.__init__
VList.__init__ = __vlist_proxyinit__


def vlist_append_proxy(self, item):
    vitem = create_variant_from_item(item)
    if vitem != None:
        self.__origappend__(vitem)

VList.__origappend__ = VList.append
VList.append = vlist_append_proxy


def vlist_setitem_proxy(self, *args):
    witem = create_variant_from_item(args[1])
    self.__orig_setitem__(args[0], witem)
    
VList.__orig_setitem__ = VList.__setitem__
VList.__setitem__ = vlist_setitem_proxy


def __vlist_repr__(self):
    buff = "["
    lsize = self.size()
    i = 0
    for item in self.iterator():
        i += 1
        buff += repr(item)
        if i < lsize:
            buff += ", "
    buff += "]"
    return buff


VList.__orig_repr__ = VList.__repr__
VList.__repr__ = __vlist_repr__


# Wrapping methods for VMap
def __vmap_setitem_proxy__(self, *args):
    witem = create_variant_from_item(args[1])
    self.__orig_setitem__(args[0], witem)

VMap.__orig_setitem__ = VMap.__setitem__
VMap.__setitem__ =  __vmap_setitem_proxy__


def __vmap_repr_proxy__(self):
    buff = "{"
    msize = self.size()
    i = 0
    for key, val in self.iteritems():
        i += 1
        buff += repr(key) + ": " + repr(val)
        if i < msize:
            buff += ", "
    buff += "}"
    return buff

VMap.__orig_repr__ = VMap.__repr__
VMap.__repr__ = __vmap_repr_proxy__
%}

%extend vtime
{
  PyObject* vtime::get_time(void)
  {
    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    PyDateTime_IMPORT;
    SWIG_PYTHON_THREAD_END_BLOCK;
    PyObject* v;

    v = PyDateTime_FromDateAndTime(self->year, self->month, self->day, 
    self->hour, self->minute, self->second, self->usecond);
    return (v);
  }
};

namespace std
{
  %template(MapString)       map<string, string>;
  //%template(ParameterMap)    map<string, Parameter* >;
  %template(MapVtime)        map<string, vtime* >;
  %template(MapInt)          map<string, unsigned int>;
};
//%traits_swigtype(Parameter);
//%fragment(SWIG_Traits_frag(Parameter));
%traits_swigtype(vtime);
%fragment(SWIG_Traits_frag(vtime));
