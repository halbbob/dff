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

%feature("director") fso;
%feature("director") mfso;
%feature("director") Node;
%feature("director") DEventHandler;


%newobject Node::open();
%newobject VFile::search();


%feature("director:except") fso
{
    if ($error != NULL)
    {
      
      throw Swig::DirectorMethodException();
    }
}

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
#ifndef WIN32
%include "stdint.i"
#else
%include "wstdint.i"
#endif
%include "windows.i"
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

%catches(vfsError) mfso::vopen(Node*);
%catches(vfsError) mfso::vread(int32_t, void*, uint32_t);
%catches(vfsError) mfso::vwrite(int32_t, void*, uint32_t);
%catches(vfsError) mfso::vseek(int32_t, uint64_t, int32_t);
%catches(vfsError) mfso::vtell(int32_t);
%catches(vfsError) mfso::vclose(int32_t);

%catches(vfsError) FdManager::remove(int32_t);
%catches(vfsError) FdManager::get(int32_t);
%catches(vfsError) FdManager::push();

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
  //    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
    //  SWIG_PYTHON_THREAD_END_ALLOW;
     // SWIG_PYTHON_THREAD_END_BLOCK;
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

%exception FdManager::remove
{
    try
    {
  //    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  //    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
    //  SWIG_PYTHON_THREAD_END_ALLOW;
     // SWIG_PYTHON_THREAD_END_BLOCK;
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

%exception FdManager::push
{
    try
    {
  //    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  //    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
    //  SWIG_PYTHON_THREAD_END_ALLOW;
     // SWIG_PYTHON_THREAD_END_BLOCK;
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

%exception FdManager::get
{
    try
    {
  //    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  //    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
    //  SWIG_PYTHON_THREAD_END_ALLOW;
     // SWIG_PYTHON_THREAD_END_BLOCK;
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


%exception read
{
    try
    {
  //    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  //    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
    //  SWIG_PYTHON_THREAD_END_ALLOW;
     // SWIG_PYTHON_THREAD_END_BLOCK;
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

%exception seek
{
    try
    {
  //    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  //    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
    //  SWIG_PYTHON_THREAD_END_ALLOW;
     // SWIG_PYTHON_THREAD_END_BLOCK;
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

%exception vopen
{
    try
    {
  //    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  //    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
    //  SWIG_PYTHON_THREAD_END_ALLOW;
     // SWIG_PYTHON_THREAD_END_BLOCK;
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

%exception vread
{
    try
    {
  //    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  //    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
    //  SWIG_PYTHON_THREAD_END_ALLOW;
     // SWIG_PYTHON_THREAD_END_BLOCK;
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

%exception vwrite
{
    try
    {
  //    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  //    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
    //  SWIG_PYTHON_THREAD_END_ALLOW;
     // SWIG_PYTHON_THREAD_END_BLOCK;
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

%exception vseek
{
    try
    {
  //    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  //    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
    //  SWIG_PYTHON_THREAD_END_ALLOW;
     // SWIG_PYTHON_THREAD_END_BLOCK;
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

%exception vtell
{
    try
    {
  //    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  //    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
    //  SWIG_PYTHON_THREAD_END_ALLOW;
     // SWIG_PYTHON_THREAD_END_BLOCK;
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

%exception close
{
    try
    {
  //    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  //    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
    //  SWIG_PYTHON_THREAD_END_ALLOW;
     // SWIG_PYTHON_THREAD_END_BLOCK;
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

%exception vclose
{
    try
    {
  //    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
  //    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
      $action
    //  SWIG_PYTHON_THREAD_END_ALLOW;
     // SWIG_PYTHON_THREAD_END_BLOCK;
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

%typemap(directorargout) (int32_t fd, void *rbuff, uint32_t size)
{
  memcpy((char *)rbuff, PyString_AsString($input) , PyString_Size($input));
  return PyString_Size($input);
}

%typemap(out) pdata*
{
  Py_XDECREF($result);
  $result = PyString_FromStringAndSize((const char *)$1->buff, $1->len);
  free($1->buff);
}

%{
  #include "DEventHandler.hpp"
  #include "exceptions.hpp"
  #include "export.hpp"
  #include "vfs.hpp"
  #include "node.hpp"
  #include "mfso.hpp"
  #include "vfile.hpp"
  //  #include "../include/variant.hpp"
%}

%include "../include/DEventHandler.hpp"
%include "../include/export.hpp"
%include "../include/exceptions.hpp"
%include "../include/vfs.hpp"
%include "../include/node.hpp"
%include "../include/mfso.hpp"
%include "../include/vfile.hpp"
 //%include "../include/variant.hpp"

namespace std
{
  %template(VecNode)    vector<Node*>;
  %template(ListNode)   list<Node*>;
  %template(SetNode)    set<Node *>;
  %template(VectChunck)  vector<chunck *>;
#ifdef 64_BITS
  %template(Listui64)	list<unsigned long int>;
#else
  %template(Listui64)	list<uint64_t>;
#endif
  //%template(MapTime)	map<string, vtime*>;
};


%extend VFS
{
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
};

%extend Node
{

%pythoncode
%{
def __iter__(self):
  for node in self.next:  
     yield node
%}

};
