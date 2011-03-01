/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __VARIANT_HPP__
#define __VARIANT_HPP__

#ifndef WIN32
#include <stdint.h>
#else
#include "wstdint.h"
#pragma warning(disable: 4290)
#endif

#include <iostream>
#include <sstream>
#include <string> 
#include <iomanip>

#include <list>
#include <map>
#include <typeinfo>

#include "path.hpp"
#include "vtime.hpp"

class typeId
{
private:
  
  std::map<std::string, uint8_t>		mapping;
  std::map<uint8_t, std::string>	rmapping;
  EXPORT typeId();
  EXPORT ~typeId();
  typeId&          operator=(typeId&);
  typeId(const typeId&);
  
  
public:
  enum Type
    {
      Invalid = 0,
      // classic types
      String = 1,
      CArray = 2,
      Char = 3,
      Int16 = 4,
      UInt16 = 5,
      Int32 = 6,
      UInt32 = 7,
      Int64 = 8,
      UInt64 = 9,
      Bool = 10,
      Map = 11,
      List = 12,
      // dff types
      VTime = 13,
      Node = 14,
      Path = 15,
      // user types
      VoidPtr = 16
    };

  static typeId   *Get()
  {
	static typeId single;
	return &single;
  }
  EXPORT uint8_t		getType(std::string type);
  EXPORT std::string	typeToName(uint8_t t);
};


class Variant
{
public:

  EXPORT Variant();
  EXPORT ~Variant();
  EXPORT Variant(std::string str);
  EXPORT Variant(char *carray);
  EXPORT Variant(char c);
  EXPORT Variant(uint16_t us);
  EXPORT Variant(int16_t s);
  EXPORT Variant(uint32_t ui);
  EXPORT Variant(int32_t i);
  EXPORT Variant(int64_t ull);
  EXPORT Variant(uint64_t ll);
  EXPORT Variant(bool b);
  EXPORT Variant(vtime *vt);
  EXPORT Variant(class Node *node);
  EXPORT Variant(class Path *path);
  EXPORT Variant(std::list<class Variant*> l);
  EXPORT Variant(std::map<std::string, class Variant*> m);
  EXPORT Variant(void *user);

  EXPORT bool	convert(uint8_t itype, void *res)
  {
    bool	ret;

    try
      {
	ret = false;
	if (itype == typeId::Int16)
	  {
	    int16_t *s = static_cast<int16_t*>(res);
	    *s = this->toInt16();
	    ret = true;
	  }
	else if (itype == typeId::UInt16)
	  {
	    uint16_t *us = static_cast<uint16_t*>(res);
	    *us = this->toUInt16();
	    ret = true;
	  }
	else if (itype == typeId::Int32)
	  {
	    int32_t *i = static_cast<int32_t*>(res);
	    *i = this->toInt32();
	    ret = true;
	  }
	else if (itype == typeId::UInt32)
	  {
	    uint32_t *ui = static_cast<uint32_t*>(res);
	    *ui = this->toUInt32();
	    ret = true;
	  }
	else if (itype == typeId::Int64)
	  {
	    int64_t *ll = static_cast<int64_t*>(res);
	    *ll = this->toInt64();
	    ret = true;
	  }
	else if (itype == typeId::UInt64)
	  {
	    uint64_t *ull = static_cast<uint64_t*>(res);
	    *ull = this->toUInt64();
	    ret = true;
	  }
	else if (itype == typeId::Char)
	  {
	    char *c = static_cast<char*>(res);
	    *c = this->toChar();
	    ret = true;
	  }
	else if (itype == typeId::CArray)
	  {
	    char **cstr = static_cast<char**>(res);
	    *cstr = this->toCArray();
	    ret = true;
	  }
	else if (itype == typeId::String)
	  {
	    std::string *str = static_cast<std::string*>(res);
	    *str = this->toString();
	    ret = true;
	  }
	else if ((itype == typeId::Node) && (this->_type == typeId::Node))
	  {
	    class Node **n = static_cast<class Node**>(res);
	    *n = (class Node*)this->__data.ptr;
	    ret = true;
	  }
	else if ((itype == typeId::Path) && (this->_type == typeId::Path))
	  {
	    class Path **p = static_cast<Path**>(res);
	    *p = (Path*)this->__data.ptr;
	    ret = true;
	  }
	else if ((itype == typeId::Bool) && (this->_type == typeId::Bool))
	  {
	    bool	*b = static_cast<bool*>(res);
	    *b = this->__data.b;
	    ret = true;
	  }
	else if ((itype == typeId::VTime) && (this->_type == typeId::VTime))
	  {
	    vtime **vt = static_cast<vtime**>(res);
	    *vt = (vtime*)this->__data.ptr;
	    ret = true;
	  }
	else if ((itype == typeId::List) && (this->_type == typeId::List))
	  {
	    std::list<Variant*> *l = static_cast<std::list<Variant*>*>(res);
	    *l = *((std::list<Variant*>*)this->__data.ptr);
	    ret = true;
	  }
	else if ((itype == typeId::Map) && (this->_type == typeId::Map))
	  {
	    std::map<std::string, Variant*> *m = static_cast<std::map<std::string, Variant*>*>(res);
	    *m = *((std::map<std::string, Variant*>*)this->__data.ptr);
	    ret = true;
	  }
	else
	  ret = false;
	return ret;
      }
    catch (std::string e)
      {
	return false;
      }
  }

  template<typename T>
  bool operator==(T val)
  {
    std::string type;
    uint8_t	itype;
    T		mine;

    itype = typeId::Get()->getType((char*)typeid(static_cast<T*>(0)).name());
    if (itype != 0)
      {
	if (this->convert(itype, &mine))
	  return (mine == val);
	else
	  return false;
      }
    else
      return false;
  }

  template<typename T>
  bool operator!=(T val)
  {
    std::string type;
    uint8_t	itype;
    T		mine;

    itype = typeId::Get()->getType((char*)typeid(static_cast<T*>(0)).name());
    if (itype != 0)
      {
	if (this->convert(itype, &mine))
	  return (mine != val);
	else
	  return true;
      }
    else
      return true;
  }

  template<typename T>
  bool operator>(T val)
  {
    std::string type;
    uint8_t	itype;
    T		mine;

    itype = typeId::Get()->getType((char*)typeid(static_cast<T*>(0)).name());
    if (itype != 0)
      {
	if (this->convert(itype, &mine))
	  return (mine > val);
	else
	  return true;
      }
    else
      return true;
  }

  template<typename T>
  bool operator>=(T val)
  {
    std::string type;
    uint8_t	itype;
    T		mine;

    itype = typeId::Get()->getType((char*)typeid(static_cast<T*>(0)).name());
    if (itype != 0)
      {
	if (this->convert(itype, &mine))
	  return (mine >= val);
	else
	  return true;
      }
    else
      return true;
  }

  template<typename T>
  bool operator<(T val)
  {
    std::string type;
    uint8_t	itype;
    T		mine;

    itype = typeId::Get()->getType((char*)typeid(static_cast<T*>(0)).name());
    if (itype != 0)
      {
	if (this->convert(itype, &mine))
	  return (mine < val);
	else
	  return false;
      }
    else
      return false;
  }

  template<typename T>
  bool operator<=(T val)
  {
    std::string type;
    uint8_t	itype;
    T		mine;

    itype = typeId::Get()->getType((char*)typeid(static_cast<T*>(0)).name());
    if (itype != 0)
      {
	if (this->convert(itype, &mine))
	  return (mine <= val);
	else
	  return false;
      }
    else
      return false;
  }

  bool	operator==(Variant* v);
  bool	operator!=(Variant* v);
  bool	operator>(Variant* v);
  bool	operator>=(Variant* v);
  bool	operator<(Variant* v);
  bool	operator<=(Variant* v);
  
  template<typename T>
  T	value(void)
  {
    std::string type;
    uint8_t	itype;
    T		t;

	itype = typeId::Get()->getType(typeid(static_cast<T*>(0)).name());

    if (itype != 0)
    {
	  if (this->convert(itype, &t))
	    return t;
	  else
	    return T();
    }
    else
	{
      return T();
	}
  }

  EXPORT std::string	toString() throw (std::string);
  EXPORT std::string	toHexString() throw (std::string);
  EXPORT std::string	toOctString() throw (std::string);
  EXPORT uint16_t	toUInt16() throw (std::string);
  EXPORT int16_t	toInt16() throw (std::string);
  EXPORT uint32_t	toUInt32() throw (std::string);
  EXPORT int32_t	toInt32() throw (std::string);
  EXPORT uint64_t	toUInt64() throw (std::string);
  EXPORT int64_t	toInt64() throw (std::string);
  EXPORT char*		toCArray() throw (std::string);
  EXPORT char		toChar() throw (std::string);
  EXPORT bool		toBool() throw (std::string);
  EXPORT uint8_t	type();
  EXPORT std::string	typeName();

private:  
  uint8_t	_type;
union Data
{
  bool b;
  char c;
  int16_t s;
  uint16_t us;
  int32_t i;
  uint32_t ui;
  int64_t ll;
  uint64_t ull;
  void *ptr;
} __data;

};

#endif
