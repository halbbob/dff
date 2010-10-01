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
 *  Frederic B. <fba@digital-forensic.org>
 */

%module(package="api.env") libenv
%feature("autodoc", 1); //1 = generate type for func proto, no work for typemap
%feature("docstring");

%feature("docstring") config
"
The config class is used for the configuration of a module. By configuration we
mean the arguments passed to a module, in command line or through the GUI.

All the possible arguments a module are stored into a list and then can be accessed from the module
when this one is running. For example, when you use the module `md5`, one argument
(a path to a file) is required : you will have to add the line add()
   add(\"\-\-file\", \"Path\", False, \"The path to the file\")
In the previous example it indicates to the module that the parameter `\-\-file` is
of type `Path` is mandatory (if it is not present, the module will stop). The last
parameter is a description and is optional.

Different types of parameters can be used, defined be the second parameter of the
add method.

Some constant configuration values can be added, such as the mime-type the module
is supposed to handle (extfs, picture, etc) by calling the method :
   add_const(\"name\", value)
where` name` is the name of the constant and `value` its value (one more time, different
types are handled; see the documentation of the `add_const` method).
"

%feature("docstring") vars
"
There must be one instance of this class for each parameters the module can take.

In other word, if the method add() from the class `config` is called three times for
the module `foo` (i.e. if the module `foo` can take three arguments), there will be
three instances of the `vars` class, used to store the different attributes composing
the argument :
    * name : the name of the parameter (`\-\-file` for example)
    * description : the description of the parameter
    * type : the type of the parameter
    * from : which module can use this parameter
    * optional : `true` if the parameter is optional, `false` otherwise.
"

%feature("docstring") argument
"
The list of arguments which are passed to a module.
"

%feature("docstring") env
"
This singleton class contains a map of all key by name.
"

%feature("docstring") results
"
This class, inheriting the `argument` class, is used to store the result of the
execution of a module.
"

%include "std_string.i"
#ifndef WIN32
%include "stdint.i"
#else
%include "wstdint.i"
#endif
%include "std_string.i" 
%include "std_list.i" 
%include "std_map.i"
%include "windows.i"
%import  "../exceptions/libexceptions.i"

%catches(envError) argument::get_int(string name);
%catches(envError) argument::get_uint64(string name);
%catches(envError) argument::get_string(string name);
%catches(envError) argument::get_bool(string name);
%catches(envError) argument::get_node(string name);
%catches(envError) argument::get_path(string name);
%catches(envError) argument::get_lnode(string name);

%catches(envError) v_val::get_int(void);
%catches(envError) v_val::get_uint64(void);
%catches(envError) v_val::get_string(void);
%catches(envError) v_val::get_bool(void);
%catches(envError) v_val::get_node(void);
%catches(envError) v_val::get_path(void);
%catches(envError) v_val::get_lnode(void);

%{
#include "../include/export.hpp"
#include "../include/env.hpp"
#include "../include/vars.hpp"
#include "../include/conf.hpp"
#include "../include/argument.hpp"
#include "../include/results.hpp"
%}
%include "../include/export.hpp"
%include "../include/env.hpp"
%include "../include/vars.hpp"
%include "../include/conf.hpp"
%include "../include/argument.hpp"
%include "../include/results.hpp"

%traits_swigtype(v_key);
%fragment(SWIG_Traits_frag(v_key));
%traits_swigtype(v_val);
%fragment(SWIG_Traits_frag(v_val));
namespace std
{
%template(ListDescr)    list<v_descr*>;
%template(MapVal)       map<string, v_val* >;
%template(ListVal)      list<v_val*>;
%template(MapKey)       map< string, v_key* >;
%template(ListNode)      list<Node*>;
};

