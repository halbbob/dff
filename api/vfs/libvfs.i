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

%module(package="api.vfs",docstring="libvfs: c++ generated inteface", directors="1") libvfs 
%feature("autodoc", 1); //1 = generate type for func proto, no work for typemap
%feature("docstring");

//%feature("director") fso;
%feature("director") mfso;
%feature("director") Node;

%newobject Node::open();
%newobject Node::attributes();
%newobject Node::fileMapping();
%newobject Node::modifiedTime();
%newobject Node::accessedTime();
%newobject Node::createdTime();

%newobject VFile::search();
//%newobject VFile::read();
//%newobject VFile::read(uint32_t);

/* %feature("director:except") fso  */
/* { */
/*     if ($error != NULL)  */
/*     { */
/*       throw Swig::DirectorMethodException(); */
/*     } */
/* } */

%feature("director:except") mfso
{
    if ($error != NULL)
    {
      throw Swig::DirectorMethodException();
    }
}

%feature("director:except") Node
{
    if ($error != NULL)
    {
      throw Swig::DirectorMethodException();
    }
}

%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "std_except.i"
%include "windows.i"
%include "stdint.i"
%import "../exceptions/libexceptions.i"

%catches(vfsError) Node::open(void);

%catches(vfsError) VFile::read(void);
%catches(vfsError) VFile::read(uint32_t);
%catches(vfsError) VFile::read(void*, uint32_t);
%catches(vfsError) VFile::write(char*, uint32_t);
%catches(vfsError) VFile::write(string);
%catches(vfsError) VFile::close(void);
%catches(vfsError) VFile::seek(uint64_t, char*);
%catches(vfsError) VFile::seek(uint64_t);
%catches(vfsError) VFile::tell(void);

/* %catches(envError) fso::start(argument* args); fso::vopen(Handle *handle); Node::open(void);  */
/* %catches(vfsError) fso::start(argument* args); fso::vopen(Handle *handle); Node::open(void);  */
/* %catches(vfsError) fso::vopen(Handle *handle); */

/* %feature("director") fso::__getstate__;  */

%exception start
{
   try
   {
       SWIG_PYTHON_THREAD_BEGIN_ALLOW;
       $action
       SWIG_PYTHON_THREAD_END_ALLOW;
   }
   catch (Swig::DirectorException e)
   {
     SWIG_PYTHON_THREAD_BEGIN_BLOCK;
     SWIG_fail;
     SWIG_PYTHON_THREAD_END_BLOCK;
   }
}

%exception open
{
    try
    {
  //    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
   //   SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
       //SWIG_PYTHON_THREAD_END_ALLOW;
    //  SWIG_PYTHON_THREAD_END_BLOCK;
    }
    catch (Swig::DirectorException e)
    {
        SWIG_fail;
    }
    catch (vfsError &e)
    {
      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
      SWIG_Python_Raise(SWIG_NewPointerObj((new vfsError(static_cast< const vfsError& >(e))),SWIGTYPE_p_vfsError, SWIG_POINTER_OWN), "vfsError", SWIGTYPE_p_vfsError);
      SWIG_PYTHON_THREAD_END_BLOCK;
      SWIG_fail;
    }
    catch (const std::exception &e)
    {
     SWIG_exception(SWIG_RuntimeError, e.what());
    }
}


%typemap(directorargout) VFile::write(void *buff , unsigned int size)
{
   memcpy((char *)buff, PyString_AsString($input) , PyString_Size($input));
}

%typemap(out) pdata*  
{
  Py_XDECREF($result);
  $result = PyString_FromStringAndSize((const char *)$1->buff, $1->len);
  free($1->buff);
}

%typemap(in) PyObject* pyfunc
{
  if (!PyCallable_Check($input))
  {
    PyErr_SetString(PyExc_TypeError, "Need a callable object!");
    return NULL;
  }
  $1 = $input;
}

%{
  #include "exceptions.hpp"
  #include "export.hpp"
  #include "vfs.hpp"
  #include "node.hpp"
  #include "fso.hpp"
  #include "mfso.hpp"
  #include "vfile.hpp"
  //  #include "../include/variant.hpp"

  static void PythonCallBack(void *data, Node* pnode)
  {
    PyObject *func, *arglist;
    PyObject *result = NULL;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    func = (PyObject *) data;
    PyObject* obj = SWIG_NewPointerObj((void *)pnode, SWIGTYPE_p_Node, 0);
    arglist = Py_BuildValue("(O)", obj) ;

    result = PyEval_CallObject(func, arglist);
    fflush(stdout); 
//  fflush(stderr);
    Py_DECREF(arglist);
    SWIG_PYTHON_THREAD_END_BLOCK;
    Py_XDECREF(result);

    return ;
  }


 static PyObject* __CBgetstate__(void* data)
 {
    PyObject *func, *result = NULL;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    func = (PyObject *) data;
    result = PyEval_CallObject(func, NULL);
    fflush(stdout); 
    SWIG_PYTHON_THREAD_END_BLOCK;
    if (!result)
      return NULL;   
    return result;
  }
%}

%include "../include/export.hpp"
%include "../include/exceptions.hpp"
%include "../include/vfs.hpp"
%include "../include/node.hpp"
%include "../include/fso.hpp"
%include "../include/mfso.hpp"
%include "../include/vfile.hpp"
 //%include "../include/variant.hpp"

namespace std
{
  %template(VecNode)    vector<Node*>;
  %template(ListNode)   list<Node*>;
  %template(SetNode)    set<Node *>;
#ifdef 64_BITS
  %template(Listui64)	list<unsigned long int>;
#else
  %template(Listui64)	list<uint64_t>;
#endif
  //%template(MapTime)	map<string, vtime*>;
};


%extend VFS
{
  void set_callback(string type, PyObject* pyfunc)
  {
    self->SetCallBack(PythonCallBack, (void* ) pyfunc, type);
    Py_INCREF(pyfunc);
  }

//XXX 64bits !
#ifdef 64_BITS
  PyObject* getNodeFromPointer(unsigned long pnode)
  {
    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    PyObject* obj = SWIG_NewPointerObj((void *)pnode, SWIGTYPE_p_Node, 0);
    SWIG_PYTHON_THREAD_END_BLOCK;
    return obj;
  }
#else
  PyObject* getNodeFromPointer(unsigned int pnode)
  {
    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    PyObject* obj = SWIG_NewPointerObj((void *)pnode, SWIGTYPE_p_Node, 0);
    SWIG_PYTHON_THREAD_END_BLOCK;
    return obj;
  }
#endif

  unsigned int getNodePointer(PyObject *obj)
  {
    unsigned int ptr;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    SWIG_ConvertPtr(obj, ((void**)&ptr), SWIGTYPE_p_Node, SWIG_POINTER_EXCEPTION);
    SWIG_PYTHON_THREAD_END_BLOCK;
    return ptr;
  }
};

%extend fso 
{
 void set_getstate(PyObject *pyfunc)
 {
   self->SetCallBack(__CBgetstate__, (void*)pyfunc);
   Py_INCREF(pyfunc);
 } 
};

//%pythoncode
//%{
//def init(self, *args):
//   print "custom Node ctor"
//   self.__originalinit__(self, *args)

//Node.__originalinit__ = Node.__init__
//Node.__init__ = init
//%}

%extend Node
{

%pythoncode
%{
def __iter__(self):
  for node in self.next:  
     yield node
%}

};
