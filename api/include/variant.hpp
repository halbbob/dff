/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
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

#include <stdint.h>
#include <iostream>
#include <list>
#include <map>
#include <typeinfo>
#include "vtime.hpp"
#include "node.hpp"

#define DEBUG 1

class typeId
{
private:
  
  static typeId			*_instance;
  std::map<char*, uint8_t>	mapping;

  typeId();
  ~typeId();
  typeId&          operator=(typeId&);
  typeId(const typeId&);
  //typeId(const typeId &);
  //typeId	&operator=(const typeId &);
  
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
      // user types
      VoidStar = 15
    };

  static typeId   *Get()
  {
    if (!_instance)
      _instance = new typeId();
    return _instance;
  }

  uint8_t	getType(char *type)
  {
    std::map<char*, uint8_t>::iterator it;
    
    it = this->mapping.find(type);
    if (it != this->mapping.end())
      return it->second;
    else
      return 0;
  }
};


class Variant
{
public:

  Variant();
  ~Variant();
  Variant(std::string str);
  Variant(char *carray);
  Variant(char c);
  Variant(uint16_t us);
  Variant(int16_t s);
  Variant(uint32_t ui);
  Variant(int32_t i);
  Variant(int64_t ull);
  Variant(uint64_t ll);
  //  Variant(bool b);
  Variant(vtime *vt);
  Variant(Node *node);
  Variant(std::list<class Variant*> l);
  Variant(std::map<std::string, class Variant*> m);
  Variant(void *user);


  bool	convert(uint8_t itype, void *res)
  {
    switch (itype)
      {
      case uint8_t(typeId::Int16):
	{
	  int16_t *s = static_cast<int16_t*>(res);
	  switch (this->_type)
	    {
	    case typeId::Int16:
	      {
		*s = this->__data.us;
		return true;
	      }
	    default:
	      return false;
	    }
	}
      case uint8_t(typeId::UInt16):
	{
	  uint16_t *s = static_cast<uint16_t*>(res);
	  switch (this->_type)
	    {
	    case typeId::UInt16:
	      {
		*s = this->__data.s;
		return true;
	      }
	    default:
	      return false;
	    }
	}
      case uint8_t(typeId::Int32):
	{
	  int32_t *s = static_cast<int32_t*>(res);
	  switch (this->_type)
	    {
	    case typeId::Int32:
	      {
		*s = this->__data.i;
		return true;
	      }
	    default:
	      return false;
	    }
	}
      case uint8_t(typeId::UInt32):
	{
	  uint32_t *s = static_cast<uint32_t*>(res);
	  switch (this->_type)
	    {
	    case typeId::UInt32:
	      {
		*s = this->__data.ui;
		return true;
	      }
	    default:
	      return false;
	    }
	}
      case uint8_t(typeId::Int64):
	{
	  int64_t *s = static_cast<int64_t*>(res);
	  switch (this->_type)
	    {
	    case typeId::Int64:
	      {
		*s = this->__data.ll;
		return true;
	      }
	    default:
	      return false;
	    }
	}
      case uint8_t(typeId::UInt64):
	{
	  uint64_t *s = static_cast<uint64_t*>(res);
	  switch (this->_type)
	    {
	    case typeId::UInt64:
	      {
		*s = this->__data.ull;
		return true;
	      }
	    default:
	      return false;
	    }
	}
      case uint8_t(typeId::Char):
	{
	  char *s = static_cast<char*>(res);
	  switch (this->_type)
	    {
	    case typeId::Char:
	      {
		*s = this->__data.c;
		return true;
	      }
	    default:
	      return false;
	    }
	}
      case uint8_t(typeId::CArray):
	{
	  char **s = static_cast<char**>(res);
	  switch (this->_type)
	    {
	    case typeId::CArray:
	      {
		*s = (char*)this->__data.ptr;
		return true;
	      }
	    default:
	      return false;
	    }
	}
      case uint8_t(typeId::String):
      {
	  std::string *str = static_cast<std::string*>(res);
          switch (this->_type)
	    {
	    case typeId::String:
	      {
		*str = ((std::string*)(this->__data.ptr))->c_str();
		return true;
	      }
	    default:
	      return false;
	    }
	}
      case uint8_t(typeId::Node):
      {
	  Node **n = static_cast<Node**>(res);
          switch (this->_type)
	    {
	    case typeId::Node:
	      {
		*n = (Node*)this->__data.ptr;
		return true;
	      }
	    default:
	      return false;
	    }
	}
      case uint8_t(typeId::VTime):
      {
	  vtime **vt = static_cast<vtime**>(res);
          switch (this->_type)
	    {
	    case typeId::VTime:
	      {
		*vt = (vtime*)this->__data.ptr;
		return true;
	      }
	    default:
	      return false;
	    }
      }
      case uint8_t(typeId::List):
      {
	std::list<Variant*> **l = static_cast<std::list<Variant*>**>(res);
	switch (this->_type)
	  {
	  case typeId::List:
	    {
	      *l = (std::list<Variant*>*)this->__data.ptr;
	      return true;
	    }
	  default:
	    return false;
	  }
	}
      case uint8_t(typeId::Map):
      {
	std::map<std::string, Variant*> **m = static_cast<std::map<std::string, Variant*>**>(res);
	switch (this->_type)
	  {
	  case typeId::Map:
	    {
	      *m = (std::map<std::string, Variant*>*)this->__data.ptr;
	      return true;
	    }
	  default:
	    return false;
	  }
	}
      default:
	return false;
      }
  }


  template<typename T>
  T	getValue(void)
  {
    std::string type;
    uint8_t	itype;
    T		t;

    itype = typeId::Get()->getType((char*)typeid(static_cast<T>(0)).name());
    if (itype != 0)
      {
	if (this->convert(itype, &t))
	  return t;
	else
	  return T();
      }
    else
      {
	printf("Unknown type\n");
	if (DEBUG)
	  {
	    printf("type id: %s\n", typeid(static_cast<T>(0)).name());
	  }
	return T();
      }
  }

  std::string	toString();
  uint16_t	toUInt16();
  int16_t	toInt16();
  uint32_t	toUInt32();
  int32_t	toInt32();
  uint64_t	toUInt64();
  int64_t	toInt64();
  bool		toBool();
  uint8_t	type();

private:  
  uint8_t	_type;
union Data
{
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
