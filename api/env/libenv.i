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

    This class is not used to get the arguments a user passed to a module, but to define a list of arguments
    the module can use. One instance of the config class is required by module.

    Let\'s take for example the `cat` viewer module (displayin the content of a Node). The viewer displays
    a given node, so it needs to know the path to what node, consequently users will have to pass at least one argument
    to cat. The config class is designed to \"tell\" the cat viewer, that one argument is required for him
    to run. Without it, the viewer will return an error and stop.
  
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

%feature("docstring") config::add
"
add(self, string name, string type, bool opt = False, string descr = "")
add(self, string name, string type, bool opt = False)
        add(self, string name, string type)
        add(self, string name, string type, int min, int max, bool opt = False, string descr = "")
        add(self, string name, string type, int min, int max, bool opt = False)
        add(self, string name, string type, int min, int max)

        Add an argument to the argument list.

        By default, the list of parameters the module can take is empty. This is
        up to the modules developer to fill a list up of possible arguments. This can be done by using
        the `add` method. Each call to this method will add a new possible arguments to the list. The name
        of the argument is defined by the first parameter `name`, the second arguement of add defines
        a type.
        
        For example, if you call :

                add(\"\-\-file\", \"Path\", \"True\", \"Some example arg\")\;

        for the module `foo`, it means that it can be invoked in DFF command line interface like this :

                dff \/> foo \-\-file Path/to/a/node
        
        In this examplem we set the `opt` parameter of the add method to True so this parameter is not required
        by the module (i.e. it is optional).
       
        Then in the module itself you can get the arguments which were passed to them (see the fso and mfso start methods).

        It means that your module will require an argument called \-\-file which is of type Path (a path
        to a file). By default, this argument will be necesaary of the module will return an error. To use
        optional parameter you must use the third arguments of `add` and set it to `True`

        The fourth argument of add is also optional and is a description, by default an empty string.

        Params :
                * name : the name of the argument (`\-\-file` for example) you want to add on the list
                * type : the type of the argument
                * opt : must be True if the arguments is optional, False otherwise. Is set to False by default.
                * descr : description of the arguments. Is empty by default.
               
"

%feature("docstring") config::add_const
"
add_const(self, string name, string val)
add_const(self, string name, bool val)
add_const(self, string name, int val)
add_const(self, string name, uint64_t val)
add_const(self, string name, Node val)
add_const(self, string name, Path val)
add_const(self, string name, ListNode val)

The add_const method is used to pass some constant configurations values to a module. Different type can be used.

Params :
        * name : the name of the constant parameter.
        * val : the value of the constant parameter.
"

%feature("docstring") vars
"
    There must be one instance of this class for each parameters the module can take.

    In other word, if the method add\(\) from the class \`config\` is called three times for
    the module \`foo\` (i.e. if the module \`foo\` can take three arguments), there will be
    three instances of the \`vars\` class, used to store the different attributes composing
    the argument :
        * name : the name of the parameter (`\-\-file` for example)
        * description : the description of the parameter
        * type : the type of the parameter
        * from : which module can use this parameter
        * optional : \`true\` if the parameter is optional, \`false\` otherwise.
"

%feature("docstring") argument
"
    The list of arguments which are passed to a module.

    This class is defferent from the config class. It contains a list of all parameters
    passed by a user to a module. If a module is called as on the following line :

      mod \-\-arg1 val1 \-\-arg2 val2

    it is necessary that these two arguments can be retrieved by the module once it is running. They are
    stored within a list accessible through the `get` method of the argument class. See the documentation
    of this method for more details.
"

%feature("docstring") argument::get
"
        get(self, string name, int v)
        get(self, string name, uint64_t v)
        get(self, string name, bool v)
        get(self, string name, Node v)
        get(self, string name, string v)
        get(self, string name, Path v)
        get(self, string name, ListNode v)

        Get the arguments which were passed to the module when it was launched. The first argument you will
        need to get is typically the parent Node of your module (i.e. the node from which the module will buidl
        its tree view). The `args` parameter contains the entire list of all the module's parameters.

        It can be done like this :

          args\-\>get(\"arg_name\", &variable)\;

        where `arg_name` is the name of the argument you want to get and `variable` the buffer where you want to store
        the value of the argument. As far as they are several types of arguments, the get method can also take several type
        of arguments.

        Params :
                * name : the name of the argument you want to get
                * v : the address of the variable in which you want to store the value corresponding to the parameter name.

"

%feature("docstring") env
"
This singleton class contains a map of all key by name.
"

%feature("docstring") results
"
    This class, inheriting the `argument` class, is used to store the result of the
    execution of a module.


    The method add_const inherited from argument must be used to set resu
"

%feature("docstring") results::add_const
"
        add_const(self, string name, string val)
        add_const(self, string name, int val)
        add_const(self, string name, uint64_t val)
        add_const(self, string name, Node val)
        add_const(self, string name, Path val)
        add_const(self, string name, ListNode val)

        Add a result to the the results list. Notice that the type of the result can be chosen by the caller.
        
        Params :
                * name : the name of the result.
                * val : the value of the parameter.
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

/* %catches(envError) argument::get_int(string name); */
/* %catches(envError) argument::get_uint64(string name); */
/* %catches(envError) argument::get_string(string name); */
/* %catches(envError) argument::get_bool(string name); */
/* %catches(envError) argument::get_node(string name); */
/* %catches(envError) argument::get_path(string name); */
/* %catches(envError) argument::get_lnode(string name); */

/* %catches(envError) v_val::get_int(void); */
/* %catches(envError) v_val::get_uint64(void); */
/* %catches(envError) v_val::get_string(void); */
/* %catches(envError) v_val::get_bool(void); */
/* %catches(envError) v_val::get_node(void); */
/* %catches(envError) v_val::get_path(void); */
/* %catches(envError) v_val::get_lnode(void); */

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

