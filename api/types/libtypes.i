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
#include "constant.hpp"
#include "argument.hpp"
#include "config.hpp"
#include "confmanager.hpp"
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

%include "../include/variant.hpp"
%include "../include/argument.hpp"
%include "../include/constant.hpp"
%include "../include/export.hpp"
%include "../include/config.hpp"
%include "../include/path.hpp"
%include "../include/Time.h"
%include "../include/vtime.hpp"
%include "../include/confmanager.hpp"

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

%extend Constant
{
  void	addValues(PyObject* obj) throw (std::string)
  {
    std::string err;
    Py_ssize_t	lsize;
    Py_ssize_t	i;
    PyObject*	item;
    std::list<Variant*>	vlist;
    Variant*		v;
    uint8_t		itype;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    itype = self->type();
    if (PyList_Check(obj))
      {
	if ((lsize = PyList_Size(obj)) == 0)
	  throw(std::string("Constant < " + self->name() + " > provided list of values is empty"));
	else
	  {
	    i = 0;
	    
	    while ((i != lsize) && err.empty())
	      {
		item = PyList_GetItem(obj, i);
		if ((v = new_Variant__SWIG_17(item, itype)) == NULL)
		  err = "Constant < " + self->name() + "  >\n provided list of values must be of type < " + typeId::Get()->typeToName(itype) + " >";
		else
		  vlist.push_back(v);
		i++;
	      }
	  }
      }
    else
      err = "Constant < " + self->name() + " > values must be a list";
    if (err.empty())
      self->addValues(vlist);
    else
      {
	vlist.clear();
	throw(err);
      }
    SWIG_PYTHON_THREAD_END_BLOCK;
  }
};

%extend Argument
{
  PyObject*	validateParams(PyObject* obj, uint16_t* ptype, int32_t* min, int32_t* max) throw(std::string)
  {
    PyObject*	ptype_obj = NULL;
    PyObject*	min_obj = NULL;
    PyObject*	max_obj = NULL;
    PyObject*	predef_obj = NULL;
    Py_ssize_t	lsize;
    int		ecode = 0;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    if ((ptype_obj = PyDict_GetItemString(obj, "type")) == NULL)
      throw(std::string("No field < type > defined for provided parameters"));
    ecode = SWIG_AsVal_unsigned_SS_short(ptype_obj, ptype);
    if (!SWIG_IsOK(ecode))
      throw(std::string("invalid type for field < type >"));

    if ((min_obj = PyDict_GetItemString(obj, "minimum")) != NULL)
      {
	if (self->inputType() != Argument::List)
	  throw(std::string("minimum must not be defined when argument does not need list of parameters"));
	if (PyInt_Check(min_obj))
	  {
	    ecode = SWIG_AsVal_int(min_obj, min);
	    if (!SWIG_IsOK(ecode))
	      throw(std::string("invalid type for field < minimum >"));
	    if (*min < 0)
	      throw(std::string("minimum must be >= 0"));
	  }
	else
	  throw(std::string("invalid type for field < minimum >"));
      }
    else
      *min = -1;

    if ((max_obj = PyDict_GetItemString(obj, "maximum")) != NULL)
      {
	if (self->inputType() != Argument::List)
	  throw(std::string("maximum must not be defined when argument does not need list of parameters"));
	if (PyInt_Check(max_obj))
	  {
	    ecode = SWIG_AsVal_int(max_obj, max);
	    if (!SWIG_IsOK(ecode))
	      throw(std::string("invalid type for field < maximum >"));
	    if (*max <= 0)
	      throw(std::string("maximum must be >= 1"));
	    if (*min >= *max)
	      throw(std::string("maximum must be greater than minimum"));
	  }
	else
	  throw(std::string("invalid type for field < maximum >"));
      }
    else
      *max = -1;

    predef_obj = PyDict_GetItemString(obj, "predefined");    
    if (predef_obj == NULL)
      {
	if (*ptype == Parameter::NotEditable)
	  throw(std::string("not editable parameters must have < predefined > field"));
      }
    else
      {
	if (!PyList_Check(predef_obj))
	  throw(std::string("< predefined > field of parameters must be a list"));
	if (*ptype == Parameter::NotEditable)
	  {
	    lsize = PyList_Size(predef_obj);
	    if (*min > lsize)
	      throw(std::string("minimum cannot be greater than length of predefined not editable parameters"));
	    else if (*min == -1)
	      *min = 1;
	    if (*max > lsize)
	      throw(std::string("maximum cannot be greater than length of predefined not editable parameters"));
	    else if (*max == -1)
	      *max = lsize;
	  }
	else if (*min == -1)
	  *min = 1;
      }
    SWIG_PYTHON_THREAD_END_BLOCK;
    return predef_obj;
  }

  void	addParameters(PyObject* obj) throw(std::string)
  {
    PyObject*	predef_obj;
    uint16_t	ptype;
    int32_t	min;
    int32_t	max;
    uint16_t	itype;
    PyObject*	item;
    Py_ssize_t	lsize;
    Py_ssize_t	i;
    Variant*	v;
    std::string	err;
    std::list<Variant*>	vlist;

    try
      {
	predef_obj = Argument_validateParams(self, obj, &ptype, &min, &max);
	//std::cout << "setted min: " << min << " setted max: " << max << std::endl;
	SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	if (predef_obj != NULL)
	  {
	    itype = self->type();
	    lsize = PyList_Size(predef_obj);
	    while ((i != lsize) && err.empty())
	      {
		item = PyList_GetItem(predef_obj, i);
		//Maybe change this call with _wrap_new_Variant to not depend on swig overload method generation (at the moment it's SWIG_17 but could change if new Variant ctor implemented...). Then use Swig_ConvertPtr to get Variant from the returned PyObject.
		if ((v = new_Variant__SWIG_17(item, itype)) == NULL)
		  err = "Argument < " + self->name() + "  >\n predefined parameters must be of type < " + typeId::Get()->typeToName(self->type()) + " >";
		else
		  vlist.push_back(v);
		i++;
	      }
	  }
	SWIG_PYTHON_THREAD_END_BLOCK;
      }
    catch (std::string e)
      {
	err = "Argument < " + self->name() + " >\n" + e;
      }
    if (!err.empty())
      {
	vlist.erase(vlist.begin(), vlist.end());
	throw(std::string(err));
      }
    else
      {
	SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	self->addParameters(vlist, ptype, min, max);
	SWIG_PYTHON_THREAD_END_BLOCK;
      }
  }
};

%extend Config
{

  bool	matchNotEditable(std::list<Variant*> params, PyObject* obj)
  {
    std::list<Variant*>::iterator	it;
    bool				found;

    found = false;
    for (it = params.begin(); it != params.end(); it++)
      {
	if (Variant_operator_Se__Se___SWIG_1(*it, obj))
	  {
	    found = true;
	    break;
	  }
      }
    return found;
  }

  Variant*	generateSingleInput(PyObject* obj, Argument* arg) throw (std::string)
  {
    Variant*	v = NULL;
    
    if ((arg != NULL) && (obj != NULL))
      {
	if ((arg->parametersType() == Parameter::NotEditable) && (!Config_matchNotEditable(self, arg->parameters(), obj)))
	  throw(std::string("Argument < " + arg->name() + " >\npredefined parameters are immutable and those provided do not correspond to available ones"));
	if (v = new_Variant__SWIG_17(obj, arg->type()))
	  {
	    if (v == NULL)
	      throw(std::string("Argument < " + arg->name() + " >\nparameter is not compatible"));
	    else if ((v->type() == typeId::String) && (v->toString().empty()))
	      {
		delete v;
		throw(std::string("Argument < " + arg->name() + " >\nprovided string cannot be empty"));    
	      }
	  }
      }
    else
      throw(std::string("values provided to generateSingleInput are not valid"));
    return v;
  }

  Variant*	generateListInput(PyObject* obj, Argument* arg) throw (std::string)
  {
    std::list<Variant*>	vlist;
    Variant*		v = NULL;
    Py_ssize_t		lsize;
    Py_ssize_t		i;
    PyObject*		item;
    std::string		err = "";
    int32_t		min;
    int32_t		max;

    if ((arg != NULL) && (obj != NULL))
      {
	if (PyList_Check(obj))
	  {
	    i = 0;
	    min = arg->minimumParameters();
	    max = arg->maximumParameters();
	    //std::cout << "min: " << min << " max: " << max << std::endl;
	    lsize = PyList_Size(obj);
	    if (lsize == 0)
	      throw(std::string("Argument < " + arg->name() + " >\nlist of parameters is empty"));
	    if ((min != -1) && (lsize < min))
	      throw(std::string("Argument < " + arg->name() + " >\nnot enough parameters provided"));
	    if ((max != -1) && (lsize > max))
	      throw (std::string("Argument < " + arg->name() + " >\ntoo many parameters provided"));
	    try
	      {
		while ((i != lsize) && err.empty())
		  {
		    item = PyList_GetItem(obj, i);
		    v = Config_generateSingleInput(self, item, arg);
		    vlist.push_back(v);
		    i++;
		  }
	      }
	    catch(std::string e)
	      {
		err = e;
	      }
	  }
	else
	  {
	    try
	      {
		v = Config_generateSingleInput(self, obj, arg);
		vlist.push_back(v);
	      }
	    catch(std::string e)
	      {
		err = e;
	      }
	  }
      }
    else
      err = "values provided to generateListInput are not valid";
    if (!err.empty())
      {
	vlist.clear();
	throw(err);
      }
    v = new Variant(vlist);
    return v;
  }
    

  std::map<std::string, Variant*>	generate(PyObject* obj) throw (std::string)
    {
      std::map<std::string, Variant*>	res;
      std::list<Argument*>		args;
      std::list<Argument*>::iterator	argit;
      Variant*				v;
      PyObject*				itemval;
      std::string			argname;
      uint16_t				itype;
      uint16_t				rtype;
      int				ecode;
      std::string			err;
    
      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
      ecode = PyDict_Check(obj);
      SWIG_PYTHON_THREAD_END_BLOCK;
      if (ecode)
	{
	  SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	  args = self->arguments();
	  argit = args.begin();
	  SWIG_PYTHON_THREAD_END_BLOCK;
	  while ((argit != args.end()) && err.empty())
	    {
	      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	      argname = (*argit)->name();
	      itype = (*argit)->inputType();
	      rtype = (*argit)->requirementType();
	      itemval = PyDict_GetItemString(obj, argname.c_str());
	      SWIG_PYTHON_THREAD_END_BLOCK;
	      if (itemval == NULL)
		{
		  if (rtype == Argument::Required)
		    err = "Argument < " + argname + " >\n this argument is required";
		}
	      else
		{
		  //std::cout << "current argument: " <<  argname << " argument type " << (*argit)->type() << " -- provided parameter type " << obj->ob_type->tp_name << std::endl;
		  try
		    {
		      if (itype == Argument::Empty)
			v = new_Variant__SWIG_17(itemval, typeId::Bool);
		      else if (itype == Argument::Single)
			v = Config_generateSingleInput(self, itemval, *argit);
		      else if (itype == Argument::List)
			v = Config_generateListInput(self, itemval, *argit);
		      if (v != NULL)
			res.insert(std::pair<std::string, Variant*>(argname, v));
		      else
			err = "Argument < " + argname + " >\n" + "parameter provided is not valid (wrong type)";
		    }
		  catch (std::string e)
		    {
			err = "Argument < " + argname + " >\n" + "parameter provided is not valid\ndetails:\n" + e;
		    }
		}
	      argit++;
	    }
	}
      else
	err = "generating configuration failed because provided value is not of type dict";
      if (!err.empty())
	{
	  res.clear();
	  throw(err);
	}
      return res;
    }

  void	addConstant(PyObject* obj) throw(std::string)
  {
    uint32_t	pydictsize;
    Constant*	constant;
    PyObject*	name_obj = 0;
    PyObject*	type_obj = 0;
    PyObject*   values_obj = 0;
    PyObject*	descr_obj = 0;
    int		ecode = 0;
    std::string	name;
    uint8_t	type;
    std::string	description;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    if (PyDict_Check(obj))
      {
	pydictsize = PyDict_Size(obj);
	SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	if ((name_obj = PyDict_GetItemString(obj, "name")) == NULL)
	  throw(std::string("No field < name > defined for current constant"));
	ecode = SWIG_AsVal_std_string(name_obj, &name);
	if (!SWIG_IsOK(ecode))
	  throw(std::string("invalid type for field < name >"));

	if (self->constantByName(name) != NULL)
	  throw(std::string("Constant < " + name + " > already added"));
	
	if ((type_obj = PyDict_GetItemString(obj, "type")) == NULL)
	  throw(std::string("Constant < " + name + ">\nfield < type > must be defined"));
	ecode = SWIG_AsVal_unsigned_SS_char(type_obj, &type);
	if (!SWIG_IsOK(ecode))
	  throw(std::string("Constant < " + name + ">\ninvalid type for field < type >"));

	if ((descr_obj = PyDict_GetItemString(obj, "description")) == NULL)
	  throw(std::string("Constant < " + name + " >\nfield < description > must be defined"));	    
	ecode = SWIG_AsVal_std_string(descr_obj, &description);
	if (!SWIG_IsOK(ecode))
	  throw(std::string("Constant < " + name + " >\ninvalid type for field < description >"));

	if ((values_obj = PyDict_GetItemString(obj, "values")) == NULL)
	  throw(std::string("Constant < " + name + ">\nfield < values > must be defined"));
	try
	  {
	    constant = new Constant(name, type, description);
	    Constant_addValues__SWIG_1(constant, values_obj);
	    self->addConstant(constant);
	  }
	catch (std::string e)
	  {
	    delete constant;
	    throw("Constant < " + name + " >\n error while processing argument\ndetails:\n" + e);
	  }
      }
    SWIG_PYTHON_THREAD_END_BLOCK;
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
    std::list<std::string>	names;

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

	if (self->argumentByName(name) != NULL)
	  throw(std::string("Argument < " + name + " > already added"));
	
	if ((input_obj = PyDict_GetItemString(obj, "input")) == NULL)
	  throw(std::string("Argument < " + name + ">\nfield < input > must be defined"));
	ecode = SWIG_AsVal_unsigned_SS_short(input_obj, &input);
	if (!SWIG_IsOK(ecode))
	  throw(std::string("Argument < " + name + ">\ninvalid type for field < input >"));

	if ((descr_obj = PyDict_GetItemString(obj, "description")) == NULL)
	  throw(std::string("Argument < " + name + " >\nfield < description > must be defined"));	    
	ecode = SWIG_AsVal_std_string(descr_obj, &description);
	if (!SWIG_IsOK(ecode))
	  throw(std::string("Argument < " + name + " >\ninvalid type for field < description >"));

	param_obj = PyDict_GetItemString(obj, "parameters");
	SWIG_PYTHON_THREAD_END_BLOCK;
	
	if (input == Argument::Empty)
	  {
	    if (param_obj != NULL)
	      throw(std::string("Argument < " + name + ">\nfield < predefined > forbidden"));
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
		  {
		    delete arg;
		    throw(std::string("Argument < " + name + ">\nparameters field is not of type dict"));
		  }
		else
		  {
		    try
		      {
			Argument_addParameters__SWIG_3(arg, param_obj);
			self->addArgument(arg);
		      }
		    catch (std::string e)
		      {
			delete arg;
			throw("Argument < " + name + " >\n error while processing argument\ndetails:\n" + e);
		      }
		  }
	      }
	    else
	      self->addArgument(arg);
	    SWIG_PYTHON_THREAD_END_BLOCK;
	  }
	else
	  throw(std::string("Argument < " + name + ">\nflags provided to field < input > are not valid"));
      }
  }
};

%extend std::map<std::string, Variant * >
{
  bool operator==(PyObject* obj)
  {
    if (PyDict_Check(obj))
      {
	//printf("std::map<std::string, Variant*>::operator==(PyObject* obj) ---> obj == PyDict\n");
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
	//printf("std::map<std::string, Variant*>::operator==(PyObject* obj) ---> obj == VMap\n");
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
		    //std::cout << "self actual key " << smit->first << "  --  provided vmap actual key " << mit->first << std::endl;
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
	//printf("std::list<Variant*>::operator==(PyObject* obj) ---> obj == PyList\n");
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
	//printf("std::list<Variant*>::operator==(PyObject* obj) ---> obj == VList\n");
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
	  //printf("Variant::Variant(PyObject* obj, uint8_t type) ---> obj == PyLong_Check || PyInt_Check provided\n");
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
	  std::string	str;

	  SWIG_PYTHON_THREAD_BEGIN_BLOCK;
	  ecode = SWIG_AsVal_std_string(obj, &str);
	  SWIG_PYTHON_THREAD_END_BLOCK;
	  if (SWIG_IsOK(ecode))
	    {
	      if (type == typeId::String)
		{
		  v = new Variant(str);
		  err = false;
		}
	      else if (type == typeId::CArray)
		{
		  v = new Variant(str.c_str());
		  err = false;
		}
	      else if (type == typeId::Char)
		{
		  char	c;
		  if (str.size() == 1)
		    {
		      c = *(str.c_str());
		      v = new Variant(c);
		      err = false;
		    }
		}
	      else if (type == typeId::Path)
		{
		  Path*		p;
		  p = new Path(str);
		  v = new Variant(p);
		  err = false;
		}
	      else if (type == typeId::Int16)
		{
		  int16_t		s;
		  std::istringstream	conv(str);
		  if (conv >> s)
		    {
		      v = new Variant(s);
		      err = false;
		    }
		}
	      else if (type == typeId::UInt16)
		{
		  uint16_t		us;
		  std::istringstream	conv(str);
		  if (conv >> us)
		    {
		      v = new Variant(us);
		      err = false;
		    }
		}
	      else if (type == typeId::Int32)
		{
		  int32_t		i;
		  std::istringstream	conv(str);
		  if (conv >> i)
		    {
		      v = new Variant(i);
		      err = false;
		    }
		}
	      else if (type == typeId::UInt32)
		{
		  int32_t		ui;
		  std::istringstream	conv(str);
		  if (conv >> ui)
		    {
		      v = new Variant(ui);
		      err = false;
		    }
		}
	      else if (type == typeId::Int64)
		{
		  int64_t		ll;
		  std::istringstream	conv(str);
		  if (conv >> ll)
		    {
		      v = new Variant(ll);
		      err = false;
		    }
		}
	      else if (type == typeId::UInt64)
		{
		  uint64_t		ull;
		  std::istringstream	conv(str);
		  if (conv >> ull)
		    {
		      v = new Variant(ull);
		      err = false;
		    }
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
	//printf("    !!! obj is NULL !!!\n");
	return false;
      }    
    if (obj->ob_type == NULL)
      {
	//printf("    !!! obj->ob_type is NULL !!!\n");
	return false;
      }
    if (obj->ob_type->tp_name == NULL)
      {
	//printf("    !!! obj->ob_type->tp_name is NULL !!!\n");
	return false;
      } 
    if (strncmp("Variant", obj->ob_type->tp_name, 7) == 0)
      {
	//printf("Variant::operator==(PyObject* obj) ---> obj == Variant\n");
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
	//printf("Variant::operator==(PyObject* obj) ---> obj == VList\n");
	std::list<Variant *> selflist;
	selflist = self->value<std::list< Variant * > >();
	return std_list_Sl_Variant_Sm__Sg__operator_Se__Se_(&selflist, obj);
      }
    else if (((strncmp("VMap", obj->ob_type->tp_name, 4) == 0) || PyDict_Check(obj)) && (type == typeId::Map))
      {
	//printf("Variant::operator==(PyObject* obj) ---> obj == VMap\n");
	std::map<std::string, Variant*> selfmap;
	selfmap = self->value<std::map<std::string, Variant* > >();
	return std_map_Sl_std_string_Sc_Variant_Sm__Sg__operator_Se__Se_(&selfmap, obj);
      }
    else if (PyLong_Check(obj) || PyInt_Check(obj))
      {
	//printf("Variant::operator==(PyObject* obj) ---> obj == PyLong_Check || PyInt_Check provided\n");
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
	//printf("    !!! obj is NULL !!!\n");
	return false;
      }    
    if (obj->ob_type == NULL)
      {
	//printf("    !!! obj->ob_type is NULL !!!\n");
	return false;
      }
    if (obj->ob_type->tp_name == NULL)
      {
	//printf("    !!! obj->ob_type->tp_name is NULL !!!\n");
	return false;
      }
    if (strncmp("Variant", obj->ob_type->tp_name, 7) == 0)
      {
	//printf("Variant::operator>(PyObject* obj) ---> obj == Variant\n");
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
	//printf("Variant::operator>(PyObject* obj) ---> obj == PyLong_Check || PyInt_Check provided\n");
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

	//printf("Variant::operator>(PyObject* obj) ---> obj == PyLong_Check || PyInt_Check provided\n");	
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
  %template(ListString)      list<string>;
  %template(ArgumentList)    std::list<Argument*>;
  %template(ConfigList)      std::list<Config*>;
  %template(ConstantList)    std::list<Constant*>;
  %template(MapVtime)        map<string, vtime* >;
  %template(MapConstant)     map<std::string, Constant*>;
  %template(MapArgument)     map<std::string, Argument*>;
  %template(MapInt)          map<string, unsigned int>;
};

%traits_swigtype(vtime);
%fragment(SWIG_Traits_frag(vtime));
