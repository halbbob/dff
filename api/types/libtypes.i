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
  //#include "parameter.hpp"
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
  static bool std_list_Sl_Variant_Sm__Sg__operator_Se__Se_(std::list< Variant * > *self,PyObject *obj);
  static bool std_map_Sl_std_string_Sc_Variant_Sm__Sg__operator_Se__Se_(std::map< std::string,Variant * > *self,PyObject *obj);
  static int SWIG_AsVal_std_string(PyObject*, std::string*);
  %}

%ignore Variant::operator==(T val);
%ignore Variant::operator!=(T val);
%ignore Variant::operator>(T val);
%ignore Variant::operator>=(T val);
%ignore Variant::operator<(T val);
%ignore Variant::operator<=(T val);
//%ignore Argument::addParameters(std::list<Variant*>);

%include "../include/variant.hpp"
 //%include "../include/parameter.hpp"
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
   else if (t == typeId::Path)
     ;
   else if (t == typeId::Node)
     ;
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
  void	addParameters(PyObject* obj) throw(std::string)
  {
    PyObject*	type_obj;
    PyObject*	predef_obj;
    uint16_t	ptype;
    int		ecode = 0;
    uint16_t	itype;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    if ((type_obj = PyDict_GetItemString(obj, "type")) == NULL)
      throw(std::string("No field < type > defined for provided parameters"));
    ecode = SWIG_AsVal_unsigned_SS_short(type_obj, &ptype);
    if (!SWIG_IsOK(ecode))
      throw(std::string("invalid type for field < type >"));

    predef_obj = PyDict_GetItemString(obj, "predefined");
    
    if (predef_obj == NULL)
      {
	if (ptype == Parameter::NotEditable)
	  throw(std::string("not editable parameters must have < predefined > field"));
      }
    else
      {
	if (!PyList_Check(predef_obj))
	  throw(std::string("< predefined > field of parameters must be a list"));
	else
	  {
	    PyObject*	item;
	    Py_ssize_t	lsize = PyList_Size(predef_obj);
	    Py_ssize_t	i;
	    itype = self->type();
	    Variant*	v;
	    bool	err = false;
	    std::list<Variant*>	vlist;

	    for (i = 0; i != lsize; i++)
	      {
		item = PyList_GetItem(predef_obj, i);
		//Maybe change this call with _wrap_new_Variant to not depend on swig overload method generation (at the moment it's SWIG_17 but could change if new Variant ctor implemented...). Then use Swig_ConvertPtr to get Variant from the returned PyObject.
		if ((v = new_Variant__SWIG_17(item, itype)) == NULL)
		  {
		    err = true;
		    break;
		  }
		else
		  vlist.push_back(v);
	      }
	    if (err)
	      {
		vlist.erase(vlist.begin(), vlist.end());
		throw(std::string("provided predefined parameters are not compatible with argument type"));
	      }
	    else
	      self->addParameters(vlist, ptype);
	  }
      }
    SWIG_PYTHON_THREAD_END_BLOCK;
  }
};

%extend Config
{

  void  generate(PyObject* obj)
  {
    std::map<std::string, Variant*>	res;
    std::list<Argument*>::iterator	argit;
    std::list<Argument*>		selfarg;
    Argument*				carg;
    uint16_t				type;
    uint16_t				rtype;
    uint16_t				itype;
    uint16_t				ptype;
    std::string				err;
    PyObject*				itemval;
    std::string				arg_name;
    bool				lbreak = false;
    int					ecode;
    Variant*				v;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    ecode = PyDict_Check(obj);
    if (ecode)
      {
	selfarg = self->arguments();
	for (argit = selfarg.begin(); argit != selfarg.end(); argit++)
	  {
	    carg = *argit;
	    arg_name = carg->name();
	    type = carg->type();
	    rtype = carg->requirementType();
	    itype = carg->inputType();
	    ptype = carg->parametersType();
	    itemval = PyDict_GetItemString(obj, arg_name.c_str());

	    if (itype == Argument::Empty)
	      {
		if (itemval == NULL)
		  {
		    bool	val = false;
		    v = new Variant(val);
		  }
		else
		  {
		    if ((v = new_Variant__SWIG_17(itemval, typeId::Bool)) == NULL)
		      err = "parameter provided to argument " + arg_name + " is not valid (wrong type)";
		    else
		      res.insert(std::pair<std::string, Variant*>(arg_name, v));
		  }
	      }
	    else
	      {
		if (itemval == NULL)
		  {
		    if (rtype == Argument::Required)
		      err = arg_name + " is a required argument but is not setted";
		  }
		else
		  {
		    if (itype == Argument::Single)
		      {
			if (PyList_Check(itemval))
			  err = "parameters provided to argument " + arg_name + " are of type list but argument takes a single value";
			else
			  {
			    if (ptype == Parameter::NotEditable)
			      {
				std::list<Variant*>	params;
				std::list<Variant*>::iterator	it;
				params = carg->parameters();
				bool			found = false;
				
				for (it = params.begin(); it != params.end(); it++)
				  if (Variant_operator_Se__Se___SWIG_1(*it, itemval))
				    found = true;
				if (found)
				  {
				    if ((v = new_Variant__SWIG_17(itemval, type)) == NULL)
				      err = "parameter provided to argument " + arg_name + " is not valid (wrong type)";
				  }
				else
				  err = "parameters porvided to " + arg_name + " are not editable and the one provided is not managed";
			      }
			    else
			      {
				if ((v = new_Variant__SWIG_17(itemval, type)) == NULL)
				  err = "parameter provided to argument " + arg_name + " is not valid (wrong type)";
			      }
			  }
		      }
		    else if (itype == Argument::List)
		      {
			if (PyList_Check(itemval))
			  {
			    if (ptype == Parameter::NotEditable)
			      {
				std::list<Variant*>	params;
				std::list<Variant*>::iterator	it;
				params = carg->parameters();
				bool			found;
				bool			lbr;
				PySize_t		size;
				PySize_t		i;
				PyObject*		cparam;
				
				size = PyList_Size(itemval);
				lbr = false;
				for (i = 0; i != size; i++)
				  {
				    found = false;
				    cparam = PyList_GetItem(i);
				    for (it = params.begin(); it != params.end(); it++)
				      if (Variant_operator_Se__Se___SWIG_1(*it, cparam))
					found = true;
				    if (!found)
				      {
					lbr = true;
					break;
				      }
				  }
				if (lbr)
				  err = "parameters porvided to " + arg_name + " are not editable and the one provided is not managed";
				else
				  if ((v = new_Variant__SWIG_17(itemval, type)) == NULL)
				    err = "parameter provided to argument " + arg_name + " is not valid (wrong type)";
			      }
			    else
			      {
				if ((v = new_Variant__SWIG_17(itemval, type)) == NULL)
				  err = "parameter provided to argument " + arg_name + " is not valid (wrong type)";
			      }
			  }
			else
			  {
			    if (ptype == Parameter::NotEditable)
			      {
				std::list<Variant*>	params;
				std::list<Variant*>::iterator	it;
				params = carg->parameters();
				bool			found = false;
				
				for (it = params.begin(); it != params.end(); it++)
				  if (Variant_operator_Se__Se___SWIG_1(*it, itemval))
				    found = true;
				if (found)
				  {
				    Variant*	tmp;
				    if ((tmp = new_Variant__SWIG_17(itemval, type)) == NULL)
				      err = "parameter provided to argument " + arg_name + " is not valid (wrong type)";
				    else
				      {
					std::list<Variant*>	vlist;
					vlist.push_back(tmp);
					v = new Variant(vlist);
					res.insert(std::pair<std::string, Variant*>(arg_name, v));
				      }
				  }
				else
				  err = "parameters porvided to " + arg_name + " are not editable and the one provided is not managed";
			      }
			    else
			      {
				Variant*	tmp;
				if ((tmp = new_Variant__SWIG_17(itemval, type)) == NULL)
				  err = "parameter provided to argument " + arg_name + " is not valid (wrong type)";
				else
				  {
				    std::list<Variant*>	vlist;
				    vlist.push_back(tmp);
				    v = new Variant(vlist);
				    res.insert(std::pair<std::string, Variant*>(arg_name, v));
				  }
			      }
			  }
		      }
		  }
	      }
	    if (!err.empty())
	      break;
	  }
	if (!err.empty())
	  res.erase(res.begin(), res.end());
      }
    else
      err = std::string("arguments must be a dictionnary");
    SWIG_PYTHON_THREAD_END_BLOCK;
    if (!err.empty())
      throw(err);
  }

  void	addArgument(PyObject* obj) throw(std::string)
  {
    uint32_t	pydictsize;
    Argument*	arg;
    PyObject*	name_obj = 0;
    PyObject*	input_obj = 0;
    PyObject*   param_obj = 0;
    PyObject*	descr_obj = 0;
    PyObject*	rtime_obj = 0;

    uint16_t	input;
    std::string	name;
    std::string	description;

    int		ecode = 0;

    if (PyDict_Check(obj))
      {
	pydictsize = PyDict_Size(obj);
	SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	if ((name_obj = PyDict_GetItemString(obj, "name")) == NULL)
	  throw(std::string("No field < name > defined for current argument"));
	ecode = SWIG_AsVal_std_string(name_obj, &name);
	if (!SWIG_IsOK(ecode))
	  throw(std::string("invalid type for field < name >"));
	
	if ((input_obj = PyDict_GetItemString(obj, "input")) == NULL)
	  throw(std::string("No field < input > defined for current argument"));
	ecode = SWIG_AsVal_unsigned_SS_short(input_obj, &input);
	if (!SWIG_IsOK(ecode))
	  throw(std::string("invalid type for field < input >"));
	if ((descr_obj = PyDict_GetItemString(obj, "description")) == NULL)
	  throw(std::string("No field < description > defined for current argument"));	    
	ecode = SWIG_AsVal_std_string(descr_obj, &description);
	if (!SWIG_IsOK(ecode))
	  throw(std::string("invalid type for field < description >"));
	
	param_obj = PyDict_GetItemString(obj, "parameters");
	SWIG_PYTHON_THREAD_END_BLOCK;
	
	if (input == Argument::Empty)
	  {
	    if (param_obj != NULL)
	      throw(std::string("parameters defined for an argument which takes no parameter"));
	    else
	      {
		SWIG_PYTHON_THREAD_BEGIN_BLOCK;
		arg = new Argument(name, input, description);
		self->addArgument(arg);
		SWIG_PYTHON_THREAD_END_BLOCK;
	      }
	  }
	else if ((
		  ((input & 0x0300) == Argument::List) || ((input & 0x0300) == Argument::Single))
		 && (((input & 0x0c00) == Argument::Optional) || ((input & 0x0c00) == Argument::Required)))
	  {
	    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	    arg = new Argument(name, input, description);
	    if (param_obj != NULL)
	      {
		if (!PyDict_Check(param_obj))
		  throw(std::string("parameters field is not of type dict"));
		else
		  {
		    try
		      {
			Argument_addParameters__SWIG_1(arg, param_obj);
			self->addArgument(arg);
		      }
		    catch (std::string e)
		      {
			delete arg;
			throw("error while parsing argument < " + name + " >\n   " + e);
		      }
		  }
	      }
	    else
	      self->addArgument(arg);
	    SWIG_PYTHON_THREAD_END_BLOCK;
	  }
	else
	  throw(std::string("flags setted to field < input > are not valid"));
      }
  }
};

%extend std::map<std::string, Variant * >
{
  bool operator==(PyObject* obj)
  {
    if (PyDict_Check(obj))
      {
	printf("std::map<std::string, Variant*>::operator==(PyObject* obj) ---> obj == PyDict\n");
	if (self->size() == PyDict_Size(obj))
	  {
	    std::map<std::string, Variant *>::const_iterator it;
	    PyObject *value;
	    for (it = self->begin(); it != self->end(); it++)
	      {
		if ((value = PyDict_GetItemString(obj, it->first.c_str())) != NULL)
		  {
		    if (!Variant_operator_Se__Se___SWIG_1(it->second, value))
		      return false;
		  }
		else
		  return false;
	      }
	    return true;
	  }
	else
	  return false;
      }
    else if (strncmp("VMap", obj->ob_type->tp_name, 5) == 0)
      {
	printf("std::map<std::string, Variant*>::operator==(PyObject* obj) ---> obj == VMap\n");
	void* argp1 = 0;
	std::map< std::string, Variant *> *arg1 = (std::map< std::string, Variant * > *) 0 ;
	int res1 = SWIG_ConvertPtr(obj, &argp1, SWIGTYPE_p_std__mapT_std__string_Variant_p_std__lessT_std__string_t_std__allocatorT_std__pairT_std__string_const_Variant_p_t_t_t, 0 | 0);
	if (SWIG_IsOK(res1))
	  {
	    arg1 = reinterpret_cast< std::map<std::string, Variant * > * >(argp1);
	    if (arg1->size() != self->size())
	      return false;
	    else
	      {
		std::map<std::string, Variant* >::iterator smit;
		std::map<std::string, Variant* >::iterator mit;
		for (smit = self->begin(), mit = arg1->begin(); smit != self->end(), mit != arg1->end(); smit++, mit++)
		  {
		    std::cout << "self actual key " << smit->first << "  --  provided vmap actual key " << mit->first << std::endl;
		    if ((smit->first != mit->first) || (!(smit->second == mit->second)))
		      return false;
		  }
		return true;
	      }
	  }
	else
	  return false;
      }
    else
      return false;
  }
};

%extend std::list<Variant * >
{

  bool operator==(PyObject* obj)
  {
    if (PyList_Check(obj))
      {
	printf("std::list<Variant*>::operator==(PyObject* obj) ---> obj == PyList\n");
	if (self->size() == PyList_Size(obj))
	  {
	    std::list<Variant *>::const_iterator it;
	    int i;
	    PyObject* item;
	    for (it = self->begin(), i = 0; it != self->end(); it++, i++)
	      {
		item = PyList_GetItem(obj, i);
		if (!Variant_operator_Se__Se___SWIG_1(*it, item))
		  return false;
	      }
	    return true;
	  }
	else
	  return false;
      }
    else if (strncmp("VList", obj->ob_type->tp_name, 5) == 0)
      {
	printf("std::list<Variant*>::operator==(PyObject* obj) ---> obj == VList\n");
	void* argp1 = 0;
	std::list< Variant *> *arg1 = (std::list< Variant * > *) 0 ;
	int res1 = SWIG_ConvertPtr(obj, &argp1, SWIGTYPE_p_std__listT_Variant_p_std__allocatorT_Variant_p_t_t, 0 | 0);
	if (SWIG_IsOK(res1))
	  {
	    arg1 = reinterpret_cast< std::list<Variant * > * >(argp1);
	    if (self->size() != arg1->size())
	      return false;
	    else
	      {
		std::list<Variant *>::iterator	sit;
		std::list<Variant *>::iterator	lit;
		for (sit = self->begin(), lit = arg1->begin(); sit != self->end(), lit != arg1->end(); sit++, lit++)
		  if (!(*lit == *sit))
		    return false;
		return true;
	      }
	  }
	else
	  return false;
      }
    else
      return false;
  }
};


%extend Variant
{

  Variant(PyObject* obj, uint8_t type) throw(std::string)
    {
      Variant*	v = NULL;
      bool	err = true;
      int	ecode;
      
      if (PyLong_Check(obj) || PyInt_Check(obj))
	{
	  printf("Variant::Variant(PyObject* obj, uint8_t type) ---> obj == PyLong_Check || PyInt_Check provided\n");
	  if (type == uint8_t(typeId::Int16))
	    {
	      int16_t	s;
	      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	      ecode = SWIG_AsVal_short(obj, &s);
	      SWIG_PYTHON_THREAD_END_BLOCK;
	      if (SWIG_IsOK(ecode))
		{
		  v = new Variant(v);
		  err = false;
		}
	    }
	  else if (type == uint8_t(typeId::UInt16))
	    {
	      uint16_t	us;
	      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	      int ecode = SWIG_AsVal_unsigned_SS_short(obj, &us);
	      SWIG_PYTHON_THREAD_END_BLOCK;
	      if (SWIG_IsOK(ecode))
		{
		  v = new Variant(us);
		  err = false;
		}
	    }
	  else if (type == uint8_t(typeId::Int32))
	    {
	      int32_t	i;
	      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	      int ecode = SWIG_AsVal_int(obj, &i);
	      SWIG_PYTHON_THREAD_END_BLOCK;
	      if (SWIG_IsOK(ecode))
		{
		  v = new Variant(i);
		  err = false;
		}
	    }
	  else if (type == uint8_t(typeId::UInt32))
	    {
	      uint32_t	ui;
	      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	      int ecode = SWIG_AsVal_unsigned_SS_int(obj, &ui);
	      SWIG_PYTHON_THREAD_END_BLOCK;
	      if (SWIG_IsOK(ecode))
		{
		  v = new Variant(ui);
		  err = false;
		}
	    }
	  else if (type == uint8_t(typeId::Int64))
	    {
	      int64_t	ll;
	      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
#ifdef SWIGWORDSIZE64
	      int ecode = SWIG_AsVal_long(obj, &ll);
#else
	      int ecode = SWIG_AsVal_long_SS_long(obj, &ll);
#endif
	      SWIG_PYTHON_THREAD_END_BLOCK;
	      if (SWIG_IsOK(ecode))
		{
		  v = new Variant(ll);
		  err = false;
		}
	    }
	  else if (type == uint8_t(typeId::UInt64))
	    {
	      uint64_t	ull;
	      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
#ifdef SWIGWORDSIZE64
	      int ecode = SWIG_AsVal_unsigned_SS_long(obj, &ull);
#else
	      int ecode = SWIG_AsVal_unsigned_SS_long_SS_long(obj, &ull);
#endif
	      SWIG_PYTHON_THREAD_END_BLOCK;
	      if (SWIG_IsOK(ecode))
		{
		  v = new Variant(ull);
		  err = false;
		}
	    }
	}
      else if (PyBool_Check(obj))
	{
	  bool	b;
	  SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	  int ecode = SWIG_AsVal_bool(obj, &b);
	  SWIG_PYTHON_THREAD_END_BLOCK;
	  if (SWIG_IsOK(ecode))
	    {
	      v = new Variant(b);
	      err = false;
	    }
	}
      else if (PyString_Check(obj))
	{
	  if (type == typeId::String)
	    {
	      std::string	str;

	      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	      ecode = SWIG_AsVal_std_string(obj, &str);
	      SWIG_PYTHON_THREAD_END_BLOCK;
	      if (SWIG_IsOK(ecode))
		{
		  v = new Variant(str);
		  err = false;
		}
	    }
	  else if (type == typeId::CArray)
	    {
	      std::string	str;

	      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	      ecode = SWIG_AsVal_std_string(obj, &str);
	      SWIG_PYTHON_THREAD_END_BLOCK;
	      if (SWIG_IsOK(ecode))
		{
		  v = new Variant(str.c_str());
		  err = false;
		}
	    }
	  else if (type == typeId::Char)
	    {
	      char	c;

	      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	      ecode = SWIG_AsVal_char(obj, &c);
	      SWIG_PYTHON_THREAD_END_BLOCK;
	      if (SWIG_IsOK(ecode))
		{
		  v = new Variant(c);
		  err = false;
		}
	    }
	  else if (type == typeId::Path)
	    {
	      std::string	str;
	      Path*		p;

	      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	      ecode = SWIG_AsVal_std_string(obj, &str);
	      SWIG_PYTHON_THREAD_END_BLOCK;
	      if (SWIG_IsOK(ecode))
		{
		  p = new Path(str);
		  v = new Variant(p);
		  err = false;
		}
	    }
	}
      else if (strncmp("Node", obj->ob_type->tp_name, 4) == 0)
	{
	  if (type == typeId::Node)
	    { 
	      void*	vptr;
	      Node*	node;
	      int res = SWIG_ConvertPtr(obj, &vptr, SWIGTYPE_p_Node, 0);
	      if (SWIG_IsOK(res))
		{
		  node = reinterpret_cast< Node * >(vptr);
		  v = new Variant(node);
		  err = false;
		}
	    }
	}
      else if (strncmp("Path", obj->ob_type->tp_name, 4) == 0)
	{
	  if (type == typeId::Path)
	    {
	      void*	vptr;
	      Path*	path;
	      int res = SWIG_ConvertPtr(obj, &vptr, SWIGTYPE_p_Path, 0);
	      if (SWIG_IsOK(res))
		{
		  path = reinterpret_cast< Path * >(vptr);
		  v = new Variant(path);
		  err = false;
		}
	    }
	}
      else if (PyList_Check(obj))
	{
	  Py_ssize_t		size = PyList_Size(obj);
	  Py_ssize_t		it;
	  PyObject*		item;
	  std::list<Variant *>	vlist;
	  Variant*		vvlist;
	  Variant*		vitem;
	  bool			lbreak = false;

	  for (it = 0; it != size; it++)
	    {
	      item = PyList_GetItem(obj, it);
	      if ((vitem = new_Variant__SWIG_17(item, type)) == NULL)
	      	{
	      	  lbreak = true;
	      	  break;
	      	}
	      vlist.push_back(vitem);
	    }
	  if (lbreak)
	    vlist.erase(vlist.begin(), vlist.end());
	  else
	    {
	      v = new Variant(vlist);
	      err = false;
	    }
	}
      if (err)
	{
	  throw(std::string("Cannot create Variant, Provided PyObject and requested type are not compatible"));
	}
      else
	return v;
    }

  bool	operator==(PyObject* obj)
  {
    Variant*	v;
    uint8_t	type;

    type = self->type();

    if (obj == NULL)
      {
	printf("    !!! obj is NULL !!!\n");
	return false;
      }    
    if (obj->ob_type == NULL)
      {
	printf("    !!! obj->ob_type is NULL !!!\n");
	return false;
      }
    if (obj->ob_type->tp_name == NULL)
      {
	printf("    !!! obj->ob_type->tp_name is NULL !!!\n");
	return false;
      } 
    if (strncmp("Variant", obj->ob_type->tp_name, 7) == 0)
      {
	printf("Variant::operator==(PyObject* obj) ---> obj == Variant\n");
	void* argp1 = 0;
	Variant *arg1 = (Variant *) 0 ;
	int res1 = SWIG_ConvertPtr(obj, &argp1, SWIGTYPE_p_Variant, 0 | 0);
	if (SWIG_IsOK(res1))
	  {
	    arg1 = reinterpret_cast< Variant * >(argp1);
	    return self->operator==(arg1);
	  }
	else
	  return false;
      }
    else if (((strncmp("VList", obj->ob_type->tp_name, 5) == 0) || PyList_Check(obj)) && (type == typeId::List))
      {
	printf("Variant::operator==(PyObject* obj) ---> obj == VList\n");
	std::list<Variant *> selflist;
	selflist = self->value<std::list< Variant * > >();
	return std_list_Sl_Variant_Sm__Sg__operator_Se__Se_(&selflist, obj);
      }
    else if (((strncmp("VMap", obj->ob_type->tp_name, 4) == 0) || PyDict_Check(obj)) && (type == typeId::Map))
      {
	printf("Variant::operator==(PyObject* obj) ---> obj == VMap\n");
	std::map<std::string, Variant*> selfmap;
	selfmap = self->value<std::map<std::string, Variant* > >();
	return std_map_Sl_std_string_Sc_Variant_Sm__Sg__operator_Se__Se_(&selfmap, obj);
      }
    else if (PyLong_Check(obj) || PyInt_Check(obj))
      {
	printf("Variant::operator==(PyObject* obj) ---> obj == PyLong_Check || PyInt_Check provided\n");
	if (type == uint8_t(typeId::Int16))
	  {
	    int16_t	v;
	    int ecode = SWIG_AsVal_short(obj, &v);
	    if (SWIG_IsOK(ecode))
	      return self->operator==<int16_t>(v);
	    else
	      return false;
	  }
	else if (type == uint8_t(typeId::UInt16))
	  {
	    uint16_t	v;
	    int ecode = SWIG_AsVal_unsigned_SS_short(obj, &v);
	    if (SWIG_IsOK(ecode))
	      return self->operator==<uint16_t>(v); 
	    else
	      return false;
	  }
	else if (type == uint8_t(typeId::Int32))
	  {
	    int32_t	v;
	    int ecode = SWIG_AsVal_int(obj, &v);
	    if (SWIG_IsOK(ecode))
	      return self->operator==<int32_t>(v); 
	    else
	      return false;
	  }
	else if (type == uint8_t(typeId::UInt32))
	  {
	    uint32_t	v;
	    int ecode = SWIG_AsVal_unsigned_SS_int(obj, &v);
	    if (SWIG_IsOK(ecode))
	      return self->operator==<uint32_t>(v);
	    else
	      return false;
	  }
	else if (type == uint8_t(typeId::Int64))
	  {
	    int64_t	v;
#ifdef SWIGWORDSIZE64
	    int ecode = SWIG_AsVal_long(obj, &v);
#else
	    int ecode = SWIG_AsVal_long_SS_long(obj, &v);
#endif
	    if (SWIG_IsOK(ecode))
	      return self->operator==<int64_t>(v);
	    else
	      return false;
	  }
	else if (type == uint8_t(typeId::UInt64))
	  {
	    uint64_t	v;
#ifdef SWIGWORDSIZE64
	    int ecode = SWIG_AsVal_unsigned_SS_long(obj, &v);
#else
	    int ecode = SWIG_AsVal_unsigned_SS_long_SS_long(obj, &v);
#endif
	    if (SWIG_IsOK(ecode))
	      return self->operator==<uint64_t>(v);
	    else
	      return false;
	  }
	else
	  return false;
      }
    else if (PyBool_Check(obj) && (type == typeId::Bool))
      {
	  bool	b;
	  SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	  int ecode = SWIG_AsVal_bool(obj, &b);
	  SWIG_PYTHON_THREAD_END_BLOCK;
	  if (SWIG_IsOK(ecode))
	    return self->operator==<bool>(v);
	  else
	    return false;
      }
    else if ((PyString_Check(obj)) && (type == typeId::String))
      {
	char*		cstr;
	
	if ((cstr = PyString_AsString(obj)) != NULL)
	  return self->operator==<std::string>(cstr);
	else
	  return false;
      }
    else
      return false;
  }


  bool	operator!=(PyObject* obj)
  {
    return (!Variant_operator_Se__Se___SWIG_1(self, obj));
  }

  bool	operator>(PyObject* obj)
  {
    Variant*	v;
    uint8_t	type;

    type = self->type();

    if (obj == NULL)
      {
	printf("    !!! obj is NULL !!!\n");
	return false;
      }    
    if (obj->ob_type == NULL)
      {
	printf("    !!! obj->ob_type is NULL !!!\n");
	return false;
      }
    if (obj->ob_type->tp_name == NULL)
      {
	printf("    !!! obj->ob_type->tp_name is NULL !!!\n");
	return false;
      }
    if (strncmp("Variant", obj->ob_type->tp_name, 7) == 0)
      {
	printf("Variant::operator>(PyObject* obj) ---> obj == Variant\n");
	void* argp1 = 0;
	Variant *arg1 = (Variant *) 0 ;
	int res1 = SWIG_ConvertPtr(obj, &argp1, SWIGTYPE_p_Variant, 0 | 0);
	if (SWIG_IsOK(res1))
	  {
	    arg1 = reinterpret_cast< Variant * >(argp1);
	    return self->operator>(arg1);
	  }
	else
	  return false;
      }
    else if (PyLong_Check(obj) || PyInt_Check(obj))
      {
	printf("Variant::operator>(PyObject* obj) ---> obj == PyLong_Check || PyInt_Check provided\n");
	if (type == uint8_t(typeId::Int16))
	  {
	    int16_t	v;
	    int ecode = SWIG_AsVal_short(obj, &v);
	    if (SWIG_IsOK(ecode))
	      return self->operator><int16_t>(v);
	    else
	      return false;
	  }
	else if (type == uint8_t(typeId::UInt16))
	  {
	    uint16_t	v;
	    int ecode = SWIG_AsVal_unsigned_SS_short(obj, &v);
	    if (SWIG_IsOK(ecode))
	      return self->operator><uint16_t>(v); 
	    else
	      return false;
	  }
	else if (type == uint8_t(typeId::Int32))
	  {
	    int32_t	v;
	    int ecode = SWIG_AsVal_int(obj, &v);
	    if (SWIG_IsOK(ecode))
	      return self->operator><int32_t>(v); 
	    else
	      return false;
	  }
	else if (type == uint8_t(typeId::UInt32))
	  {
	    uint32_t	v;
	    int ecode = SWIG_AsVal_unsigned_SS_int(obj, &v);
	    if (SWIG_IsOK(ecode))
	      return self->operator><uint32_t>(v);
	    else
	      return false;
	  }
	else if (type == uint8_t(typeId::Int64))
	  {
	    int64_t	v;
#ifdef SWIGWORDSIZE64
	    int ecode = SWIG_AsVal_long(obj, &v);
#else
	    int ecode = SWIG_AsVal_long_SS_long(obj, &v);
#endif
	    if (SWIG_IsOK(ecode))
	      return self->operator><int64_t>(v);
	    else
	      return false;
	  }
	else if (type == uint8_t(typeId::UInt64))
	  {
	    uint64_t	v;
#ifdef SWIGWORDSIZE64
	    int ecode = SWIG_AsVal_unsigned_SS_long(obj, &v);
#else
	    int ecode = SWIG_AsVal_unsigned_SS_long_SS_long(obj, &v);
#endif
	    if (SWIG_IsOK(ecode))
	      return self->operator><uint64_t>(v);
	    else
	      return false;
	  }
	else
	  return false;
      }
    else if ((PyString_Check(obj)) && (type == typeId::String))
      {
	char*		cstr;

	printf("Variant::operator>(PyObject* obj) ---> obj == PyLong_Check || PyInt_Check provided\n");	
	if ((cstr = PyString_AsString(obj)) != NULL)
	  return self->operator><std::string>(cstr);
	else
	  return false;
      }
    else
      return false;
  }


  bool	operator<(PyObject* obj)
  {
    if (Variant_operator_Se__Se___SWIG_1(self, obj))
      return false;
    else
      return (!Variant_operator_Sg___SWIG_1(self, obj));
  }

  bool	operator>=(PyObject* obj)
  {
    if (Variant_operator_Sg___SWIG_1(self, obj) || Variant_operator_Se__Se___SWIG_1(self, obj))
      return true;
    else
      return false;
  }

  bool	operator<=(PyObject* obj)
  {
    if (Variant_operator_Sl___SWIG_1(self, obj) || Variant_operator_Se__Se___SWIG_1(self, obj))
      return true;
    else
      return false;    
  }


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
  %template(ArgumentList)	std::list<Argument*>;
  //%template(ParameterMap)    map<string, Parameter* >;
  %template(MapVtime)        map<string, vtime* >;
  %template(MapInt)          map<string, unsigned int>;
};
//%traits_swigtype(Parameter);
//%fragment(SWIG_Traits_frag(Parameter));
%traits_swigtype(vtime);
%fragment(SWIG_Traits_frag(vtime));
