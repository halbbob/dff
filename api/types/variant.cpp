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

#include "variant.hpp"
#include "typeinfo"
#include "string.h"

typeId*	typeId::Get()
{
	static typeId single;
	return &single;
}


typeId::typeId()
{
  this->mapping.insert(std::pair<std::string, uint8_t>( typeid(int16_t*).name(), typeId::Int16));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(uint16_t*).name(), typeId::UInt16));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(int32_t*).name(), typeId::Int32));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(uint32_t*).name(), typeId::UInt32));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(int64_t*).name(), typeId::Int64));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(uint64_t*).name(), typeId::UInt64));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(char*).name(), typeId::Char));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(bool*).name(), typeId::Bool));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(char**).name(), typeId::CArray));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(void**).name(), typeId::VoidPtr));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(std::string *).name(), typeId::String));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(class vtime**).name(), typeId::VTime));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(class Node**).name(), typeId::Node));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(class Path * *).name(), typeId::Path));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(class Argument * *).name(), typeId::Argument));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(std::map<std::string, class Variant*> *).name(), typeId::Map));
  this->mapping.insert(std::pair<std::string, uint8_t>(typeid(std::list<class Variant*> *).name(), typeId::List));


  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Invalid, "Invalid"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::String, "std::string"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Int16, "int16_t"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::UInt16, "uint16_t"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Int32, "int32_t"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::UInt32, "uint32_t"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Int64, "int64_t"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::UInt64, "uint64_t"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Bool, "bool"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Map, "std::map<std::string, Variant*>"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::List, "std::list<Variant*>"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::VTime, "vtime*"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Node, "Node*"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Path, "Path*"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::Argument, "Argument*"));
  this->rmapping.insert(std::pair<uint8_t, std::string>(typeId::VoidPtr, "void*"));
  //this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(std::vector<class Variant*> *).name(), typeId::List));
  //this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(std::set<class Variant*> *).name(), typeId::List));
}

typeId::~typeId()
{
  //  delete this->mapping;
}


uint8_t	typeId::getType(std::string type)
{
  std::map<std::string, uint8_t>::iterator it;
  
  it = this->mapping.find(type);
  if (it != this->mapping.end())
    {
      return it->second;
    }
  else
    {
      return 0;
    }
}

std::string	typeId::typeToName(uint8_t t)
{
  std::map<uint8_t, std::string>::iterator it;
  
  it = this->rmapping.find(t);
  if (it != this->rmapping.end())
    return it->second;
  else
    return "";
}


Variant::Variant()
{
  this->_type = typeId::Invalid;
}

Variant::~Variant()
{
}

Variant::Variant(std::string str)
{
  this->__data.str = new std::string(str);
  this->_type = typeId::String;
}

Variant::Variant(char *carray)
{
  this->__data.str = new std::string(carray);
  this->_type = typeId::CArray;
}

Variant::Variant(char c)
{
  this->__data.c = c;
  this->_type = typeId::Char;
}

Variant::Variant(int16_t s)
{
  this->__data.s = s;
  //std::cout << "Variant(int16_t) " << s << std::endl;
  this->_type = typeId::Int16;
}

Variant::Variant(uint16_t us)
{
  this->__data.us = us;
  //std::cout << "Variant(uint16_t) " << us << std::endl;
  this->_type = typeId::UInt16;
}

Variant::Variant(int32_t i)
{
  this->__data.i = i;
  //std::cout << "Variant(int32_t) " << i << std::endl;
  this->_type = typeId::Int32;
}

Variant::Variant(uint32_t ui)
{
  this->__data.ui = ui;
  //std::cout << "Variant(uint32_t) " << ui << std::endl;
  this->_type = typeId::UInt32;
}

Variant::Variant(int64_t ll)
{
  this->__data.ll = ll;
  //std::cout << "Variant(int64_t) " << ll << std::endl;
  this->_type = typeId::Int64;
}

Variant::Variant(uint64_t ull)
{
  this->__data.ull = ull;
  //std::cout << "Variant(uint64_t) " << ull << std::endl;
  this->_type = typeId::UInt64;
}

Variant::Variant(bool b)
{
  this->__data.b = b;
  //std::cout << "Variant(bool) " << b << std::endl;
  this->_type = typeId::Bool;
}

Variant::Variant(vtime *vt)
{
  this->__data.ptr = (void*)vt;
  //std::cout << "Variant(vtime)" << std::endl;
  this->_type = typeId::VTime;
}

Variant::Variant(class Node *node)
{
  this->__data.ptr = node;
  //std::cout << "Variant(Node*)" << std::endl;
  this->_type = typeId::Node;
}

Variant::Variant(Path *path)
{
  this->__data.ptr = path;
  //std::cout << "Variant(Path*)" << std::endl;
  this->_type = typeId::Path;
}

Variant::Variant(Argument *arg)
{
  this->__data.ptr = arg;
  //std::cout << "Variant(Argument*)" << std::endl;
  this->_type = typeId::Argument;
}

Variant::Variant(std::list<Variant*> l)
{
  this->__data.ptr = (void*)new std::list<Variant*>(l);
  //std::cout << "Variant(std::list<Variant*>)" << std::endl;
  this->_type = typeId::List;
}

Variant::Variant(std::map<std::string, Variant*> m)
{
  this->__data.ptr = (void*)new std::map<std::string, Variant *>(m);
  //std::cout << "Variant(std::map<std::string, Variant*>)" << std::endl;
  this->_type = typeId::Map;
}

Variant::Variant(void *user)
{
  this->__data.ptr = (void*)user;
  //std::cout << "Variant(void*)" << std::endl;
  this->_type = typeId::VoidPtr;
}

std::string	Variant::toString() throw (std::string)
{
  std::stringstream	res;

  if (this->_type == typeId::Int16)
    res << this->__data.s;
  else if (this->_type == typeId::UInt16)
    res << this->__data.us;
  else if (this->_type == typeId::Int32)
    res << this->__data.i;
  else if (this->_type == typeId::UInt32)
    res << this->__data.ui;
  else if (this->_type == typeId::Int64)
    res << this->__data.ll;
  else if (this->_type == typeId::UInt64)
    res << this->__data.ull;
  else if (this->_type == typeId::Char)
    res << this->__data.c;
  else if (this->_type == typeId::CArray)
    res << *(this->__data.str);
  else if (this->_type == typeId::String)
    res << *(this->__data.str);
  else if (this->_type == typeId::Path)
    {
      class Path*	p;
      p = static_cast<class Path*>(this->__data.ptr);
      res << p->path;
    }
  else if (this->_type == typeId::Bool)
    {
      if (this->__data.b)
	res << "True";
      else
	res << "False";
    }
  else
    throw std::string("Cannot convert type < " + this->typeName() + " > to < std::string >");
  return res.str();
}

#include <stdio.h>

std::string	Variant::toHexString() throw (std::string)
{
  std::stringstream	res;
  
  if (this->_type == typeId::UInt16)
    res << "0x" << std::setw(2) << std::setfill('0') << std::hex << this->__data.us;
  else if (this->_type == typeId::UInt32)
    res << "0x" << std::setw(2) << std::setfill('0') << std::hex << this->__data.ui;
  else if (this->_type == typeId::UInt64)
    res << "0x" << std::setw(2) << std::setfill('0') << std::hex << this->__data.ull;
  else if (this->_type == typeId::Int16)
    res << "0x" << std::setw(2) << std::setfill('0') << std::hex << this->__data.s;
  else if (this->_type == typeId::Int32)
    res << "0x" << std::setw(2) << std::setfill('0') << std::hex << this->__data.i;
  else if (this->_type == typeId::Int64)
    res << "0x" << std::setw(2) << std::setfill('0') << std::hex << this->__data.ll;
  else if (this->_type == typeId::Char)
    res << "0x" << std::setw(2) << std::setfill('0') << std::hex << this->__data.c;
  else if ((this->_type == typeId::CArray) || (this->_type == typeId::String))
    {
      std::string::iterator	it;
      std::string		str = *(this->__data.str);

      for (it = str.begin(); it != str.end(); it++)
	{
	  res << std::setw(2) << std::setfill('0') << std::hex << static_cast<unsigned int>(static_cast<unsigned char>(*it));
	  res << " ";
	}
    }
  else
    throw std::string("Cannot represent type < " + this->typeName() + " > to an hexadecimal string");
  return res.str();
}

std::string	Variant::toOctString() throw (std::string)
{
  std::stringstream	res;
  
  res << std::oct << std::setiosflags (std::ios_base::showbase);
  if (this->_type == typeId::UInt16)
    res << this->__data.us;
  else if (this->_type == typeId::UInt32)
    res << this->__data.ui;
  else if (this->_type == typeId::UInt64)
    res << this->__data.ull;
  else if (this->_type == typeId::Int16)
    res << this->__data.s;
  else if (this->_type == typeId::Int32)
    res << this->__data.i;
  else if (this->_type == typeId::Int64)
    res << this->__data.ll;
  else if (this->_type == typeId::Char)
    res << this->__data.c;
  else
    throw std::string("Cannot represent type < " + this->typeName() + " > to an octal string");
  return res.str();
}

uint16_t	Variant::toUInt16() throw (std::string)
{
  uint16_t		res;
  std::stringstream	err;

  if (this->_type == typeId::UInt16)
    res = this->__data.us;
  else if (this->_type == typeId::UInt32)
    if (this->__data.ui <= UINT16_MAX)
      res = static_cast<uint16_t>(this->__data.ui);
    else
      err << "value [ " << this->__data.ui;
  else if (this->_type == typeId::UInt64)
    if (this->__data.ull <= UINT16_MAX)
      res = static_cast<uint16_t>(this->__data.ull);
    else
      err << "value [ " << this->__data.ull;
  else if (this->_type == typeId::Int16)
    if (this->__data.s >= 0)
      res = static_cast<uint16_t>(this->__data.s);
    else
      err << "value [ " << this->__data.s;
  else if (this->_type == typeId::Int32)
    if ((this->__data.i >= 0) && (this->__data.i <= UINT16_MAX))
      res = static_cast<uint16_t>(this->__data.i);
    else
      err << "value [ " << this->__data.i;
  else if (this->_type == typeId::Int64)
    if ((this->__data.ll >= 0) && (this->__data.ll <= UINT16_MAX))
      res = static_cast<uint16_t>(this->__data.ll);
    else
      err << "value [ " << this->__data.ll;
  else if (this->_type == typeId::Char)
    if (this->__data.c >= 0)
      res = static_cast<uint16_t>(this->__data.c);
    else
      err << "value [ " << this->__data.c;
  else if (this->_type == typeId::CArray)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else if (this->_type == typeId::String)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else
    throw std::string("type < " + this->typeName() + " > cannot be converted to < uint16_t >");
  if (!(err.str().empty()))
    {
      err << " ] of type < " << this->typeName() << " > does not fit in type < uint16_t >";
      throw err.str();
    }
  else
    return res;
}

int16_t		Variant::toInt16() throw (std::string)
{
  int16_t		res;
  std::stringstream	err;
  
  if (this->_type == typeId::Int16)
    res = this->__data.s;
  else if (this->_type == typeId::Int32)
    if ((this->__data.i >= INT16_MIN) && (this->__data.i <= INT16_MAX))
      res = static_cast<int16_t>(this->__data.i);
    else
      err << "value [ " << this->__data.i;
  else if (this->_type == typeId::Int64)
    if ((this->__data.ll >= INT16_MIN) && (this->__data.ll <= INT16_MAX))
      res = static_cast<int16_t>(this->__data.ll);
    else
      err << "value [ " << this->__data.ll;
  else if (this->_type == typeId::UInt16)
    if (this->__data.us <= INT16_MAX)
      res = static_cast<int16_t>(this->__data.us);
    else
      err << "value [ " << this->__data.us;
  else if (this->_type == typeId::UInt32)
    if (this->__data.ui <= INT16_MAX)
      res = static_cast<int16_t>(this->__data.ui);
    else
      err << "value [ " << this->__data.ui;
  else if (this->_type == typeId::UInt64)
    if (this->__data.ull <= INT16_MAX)
      res = static_cast<int16_t>(this->__data.ull);
    else
      err << "value [ " << this->__data.ull;
  else if (this->_type == typeId::Char)
    res = static_cast<int16_t>(this->__data.c);
  else if (this->_type == typeId::CArray)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else if (this->_type == typeId::String)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else
    throw std::string("type < " + this->typeName() + " > cannot be converted to < int16_t >");
  if (!(err.str().empty()))
    {
      err << " ] of type < " << this->typeName() << " > does not fit in type < int16_t >";
      throw err.str();
    }
  else
    return res;
}

uint32_t	Variant::toUInt32() throw (std::string)
{
  uint32_t		res;
  std::stringstream	err;
  
  if (this->_type == typeId::UInt16)
    res = static_cast<uint32_t>(this->__data.us);
  else if (this->_type == typeId::UInt32)
    res = this->__data.ui;
  else if (this->_type == typeId::UInt64)
    if (this->__data.ull <= UINT32_MAX)
      res = static_cast<uint32_t>(this->__data.ull);
    else
      err << "value [ " << this->__data.ull;
  else if (this->_type == typeId::Int16)
    if (this->__data.s >= 0)
      res = static_cast<uint32_t>(this->__data.s);
    else
      err << "value [ " << this->__data.s;
  else if (this->_type == typeId::Int32)
    if (this->__data.i >= 0)
      res = static_cast<uint32_t>(this->__data.i);
    else
      err << "value [ " << this->__data.i;
  else if (this->_type == typeId::Int64)
    if ((this->__data.ll >= 0) && (this->__data.ll <= UINT32_MAX))
      res = static_cast<uint32_t>(this->__data.ll);
    else
      err << "value [ " << this->__data.ll;
  else if (this->_type == typeId::Char)
    if (this->__data.c >= 0)
      res = static_cast<uint32_t>(this->__data.c);
    else
      err << "value [ " << this->__data.c;
  else if (this->_type == typeId::CArray)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else if (this->_type == typeId::String)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else
    throw std::string("type < " + this->typeName() + " > cannot be converted to < uint32_t >");
  if (!(err.str().empty()))
    {
      err << " ] of type < " << this->typeName() << " > does not fit in type < uint32_t >";
      throw err.str();
    }
  else
    return res;
}

int32_t		Variant::toInt32() throw (std::string)
{
  int32_t		res;
  std::stringstream	err;
  
  if (this->_type == typeId::Int16)
    res = static_cast<int32_t>(this->__data.s);
  else if (this->_type == typeId::Int32)
    res = this->__data.i;
  else if (this->_type == typeId::Int64)
    if ((this->__data.ll >= INT32_MIN) && (this->__data.ll <= INT32_MAX))
      res = static_cast<int32_t>(this->__data.ll);
    else
      err << "value [ " << this->__data.ll;
  else if (this->_type == typeId::UInt16)
    res = static_cast<int32_t>(this->__data.us);
  else if (this->_type == typeId::UInt32)
    if (this->__data.ui <= INT32_MAX)
      res = static_cast<int32_t>(this->__data.ui);
    else
      err << "value [ " << this->__data.ui;
  else if (this->_type == typeId::UInt64)
    if (this->__data.ull <= INT32_MAX)
      res = static_cast<int32_t>(this->__data.ull);
    else
      err << "value [ " << this->__data.ull;
  else if (this->_type == typeId::Char)
    res = static_cast<int32_t>(this->__data.c);
  else if (this->_type == typeId::CArray)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else if (this->_type == typeId::String)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else
    throw std::string("type < " + this->typeName() + " > cannot be converted to < int32_t >");
  if (!(err.str().empty()))
    {
      err << " ] of type < " << this->typeName() << " > does not fit in type < int32_t >";
      throw err.str();
    }
  else
    return res;
}

uint64_t	Variant::toUInt64() throw (std::string)
{
  uint64_t		res;
  std::stringstream	err;
  
  if (this->_type == typeId::UInt16)
    res = static_cast<uint64_t>(this->__data.us);
  else if (this->_type == typeId::UInt32)
    res = static_cast<uint64_t>(this->__data.ui);
  else if (this->_type == typeId::UInt64)
    res = this->__data.ull;
  else if (this->_type == typeId::Int16)
    if (this->__data.s >= 0)
      res = static_cast<uint64_t>(this->__data.s);
    else
      err << "value [ " << this->__data.s;
  else if (this->_type == typeId::Int32)
    if (this->__data.i >= 0)
      res = static_cast<uint64_t>(this->__data.i);
    else
      err << "value [ " << this->__data.i;
  else if (this->_type == typeId::Int64)
    if (this->__data.ll >= 0)
      res = static_cast<uint64_t>(this->__data.ll);
    else
      err << "value [ " << this->__data.ll;
  else if (this->_type == typeId::Char)
    if (this->__data.c >= 0)
      res = static_cast<uint64_t>(this->__data.c);
    else
      err << "value [ " << this->__data.c;
  else if (this->_type == typeId::CArray)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else if (this->_type == typeId::String)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else
    throw std::string("type < " + this->typeName() + " > cannot be converted to < uint64_t >");
  if (!(err.str().empty()))
    {
      err << " ] of type < " << this->typeName() << " > does not fit in type < uint64_t >";
      throw err.str();
    }
  else
    return res;
}

int64_t		Variant::toInt64() throw (std::string)
{
  int64_t		res;
  std::stringstream	err;
  
  if (this->_type == typeId::Int16)
    res = static_cast<int64_t>(this->__data.s);
  else if (this->_type == typeId::Int32)
    res = static_cast<int64_t>(this->__data.i);
  else if (this->_type == typeId::Int64)
    res = this->__data.ll;
  else if (this->_type == typeId::UInt16)
    res = static_cast<int64_t>(this->__data.us);
  else if (this->_type == typeId::UInt32)
    res = static_cast<int64_t>(this->__data.ui);
  else if (this->_type == typeId::UInt64)
    if (this->__data.ull <= INT64_MAX)
      res = static_cast<int64_t>(this->__data.ull);
    else
      err << "value [ " << this->__data.ull;
  else if (this->_type == typeId::Char)
    res = static_cast<int64_t>(this->__data.c);
  else if (this->_type == typeId::CArray)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else if (this->_type == typeId::String)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else
    throw std::string("type < " + this->typeName() + " > cannot be converted to < int64_t >");
  if (!(err.str().empty()))
    {
      err << " ] of type < " << this->typeName() << " > does not fit in type < int64_t >";
      throw err.str();
    }
  else
    return res;
}

char*	Variant::toCArray() throw (std::string)
{
  char		*res;
  std::string	str;

  try
    {
      res = new char[this->__data.str->size() + 1];
      memcpy(res, this->__data.str->c_str(), this->__data.str->size());
      res[this->__data.str->size()] = '\0';
    }
  catch (std::string e)
    {
      throw std::string("Cannot convert type < " + this->typeName() + " > to type <char*>");
    }
  return res;
}

char	Variant::toChar() throw (std::string)
{
  char			res;
  std::stringstream	err;

  if (this->_type == typeId::Char)
    res = this->__data.c;

  if (this->_type == typeId::Int16)
    if ((this->__data.s >= INT8_MIN) && (this->__data.s <= INT8_MAX))
      res = static_cast<char>(this->__data.s);
    else
      err << "value [ " << this->__data.s;

  else if (this->_type == typeId::Int32)
    if ((this->__data.i >= INT8_MIN) && (this->__data.i <= INT8_MAX))
      res = static_cast<char>(this->__data.i);
    else
      err << "value [ " << this->__data.i;

  else if (this->_type == typeId::Int64)
    if ((this->__data.ll >= INT8_MIN) && (this->__data.ll <= INT8_MAX))
      res = static_cast<char>(this->__data.ll);
    else
      err << "value [ " << this->__data.ll;

  else if (this->_type == typeId::UInt16)
    if ((this->__data.us >= INT8_MIN) && (this->__data.us <= INT8_MAX))
      res = static_cast<char>(this->__data.us);
    else
      err << "value [ " << this->__data.us;

  else if (this->_type == typeId::UInt32)
    if (this->__data.ui <= INT8_MAX)
      res = static_cast<char>(this->__data.ui);
    else
      err << "value [ " << this->__data.ui;

  else if (this->_type == typeId::UInt64)
    if(this->__data.ull <= INT8_MAX)
      res = static_cast<char>(this->__data.ull);
    else
      err << "value [ " << this->__data.ull;

  else if (this->_type == typeId::CArray)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else if (this->_type == typeId::String)
    {
      std::istringstream istr(*(this->__data.str));
      if (!(istr >> res))
	err << "value [ " << *(this->__data.str);
    }
  else
    throw std::string("type < " + this->typeName() + " > cannot be converted to < char >");
  if (!(err.str().empty()))
    {
      err << " ] of type < " << this->typeName() << " > does not fit in type < char >";
      throw err.str();
    }
  else
    return res;
}

bool		Variant::toBool() throw (std::string)
{
  if (this->_type == typeId::Bool)
    return this->__data.b;
  else
    throw (std::string("value of type < " + this->typeName() + " > cannot be converted to < bool >"));
}

uint8_t		Variant::type()
{
  return this->_type;
}

std::string	Variant::typeName()
{
  return typeId::Get()->typeToName(this->_type);
}

bool	Variant::operator==(Variant* v)
{
  std::stringstream	tmp;

  if (v == NULL)
    return false;

  try
    {
      if (this->_type == typeId::Char)
	return (this->toChar() == v->toChar());

      else if (this->_type == typeId::Int16)
	return this->toInt16() == v->toInt16();

      else if (this->_type == typeId::Int32)
	return this->toInt32() == v->toInt32();

      else if (this->_type == typeId::Int64)
	return this->toInt64() == v->toInt64();

      else if (this->_type == typeId::UInt16)
	{
	  return this->toUInt16() == v->toUInt16();
	}

      else if (this->_type == typeId::UInt32)
	return this->toUInt32() == v->toUInt32();

      else if (this->_type == typeId::UInt64)
	return this->toUInt64() == v->toUInt64();
      
      else if (this->_type == typeId::Bool)
	return this->toBool() == v->toBool();

      else if (this->_type == typeId::String)
	{
	  if ((v->type() == typeId::String) || (v->type() == typeId::CArray) || (v->type() == typeId::Char))
	    {
	      std::string	mine;
	      std::string	other;
	      
	      mine = this->toString();
	      other = v->toString();
	      return (mine == other);
	    }
	  else
	    return false;
	}

      else if (this->_type == typeId::Map)
	{
	  std::map<std::string, Variant* >		mine;
	  std::map<std::string, Variant* >		other;
	  std::map<std::string, Variant* >::iterator	mit;
	  std::map<std::string, Variant* >::iterator	oit;
	  
	  mine = *(static_cast<std::map<std::string, Variant*> * >(this->__data.ptr));
	  other = v->value<std::map<std::string, Variant* > >();
	  if (other.size() == mine.size())
	    {
	      for (mit = mine.begin(), oit = other.begin();
		   mit != mine.end(), oit != other.end();
		   mit++, oit++)
		if ((mit->first != oit->first) || (!(*(mit->second) == oit->second)))
		  return false;
	      return true;
	    }
	  else
	    return false;
	}
      else if (this->_type == typeId::List)
	{
	  std::list<Variant* >			mine;
	  std::list<Variant* >			other;
	  std::list<Variant* >::iterator	mit;
	  std::list<Variant* >::iterator	oit;

	  mine = *(static_cast<std::list<Variant*> * >(this->__data.ptr));
	  other = v->value<std::list<Variant* > >();
	  if (other.size() == mine.size())
	    {
	      for (mit = mine.begin(), oit = other.begin(); 
		   mit != mine.end(), oit != other.end();
		   mit++, oit++)
		if (!(*(*mit) == *oit))
		  return false;
	      return true;
	    }
	  else
	    return false;
	}
      else
	return false;
    }
  catch (std::string e)
    {
      return false;
    }
}

bool	Variant::operator!=(Variant* v)
{
  return !(this->operator==(v));
}

bool	Variant::operator>(Variant* v)
{
  int64_t	ll;
  uint64_t	ull;

  int64_t	oll;
  uint64_t	oull;
  uint8_t	otype;

  if (v == NULL)
    return true;

  if (this->operator==(v))
    return false;

  otype = v->type();
  if ((this->_type == typeId::Char) ||
      (this->_type == typeId::Int16) ||
      (this->_type == typeId::Int32) ||
      (this->_type == typeId::Int64))
    {
      ll = this->toInt64();
      if ((otype == typeId::Char) ||
	  (otype == typeId::Int16) ||
	  (otype == typeId::Int32) ||
	  (otype == typeId::Int64))
	return (ll > v->toInt64());
      
      else if ((ll >= 0) &&
	       ((otype == typeId::UInt16) ||
		(otype == typeId::UInt32) ||
		(otype == typeId::UInt64)))
	{
	  ull = static_cast<uint64_t>(ll);
	  return (ull > v->toUInt64());
	}
      //else if (otype == typeId::Bool)
      //	return True;
      else
	return false;
    }
  else if ((this->_type == typeId::UInt16) ||
	   (this->_type == typeId::UInt32) ||
	   (this->_type == typeId::UInt64))
    {
      ull = this->toUInt64();
      if ((otype == typeId::UInt16) ||
	  (otype == typeId::UInt32) ||
	  (otype == typeId::UInt64))
	return (ull > v->toUInt64());
      else if ((otype == typeId::Char) ||
	       (otype == typeId::Int16) ||
	       (otype == typeId::Int32) ||
	       (otype == typeId::Int64))
	{
	  oll = v->toInt64();
	  if (oll >= 0)
	    {
	      oull = static_cast<uint64_t>(oll);
	      return (ull > oull);
	    }
	  else
	    return true;
	}
      else
	return false;
    }
  //else if (this->_type == typeId::Bool)
  else if (this->_type == typeId::String)
    {
      if ((v->type() == typeId::String) || (v->type() == typeId::CArray) || (v->type() == typeId::Char))
	{
	  std::string	mine;
	  std::string	other;
	  
	  mine = this->toString();
	  other = v->toString();
	  return (mine > other);
	}
      else
	return true;
    }
  return false;
}

bool	Variant::operator>=(Variant* v)
{
  if (this->operator>(v) || this->operator==(v))
    return true;
  else
    return false;
}

bool	Variant::operator<(Variant* v)
{
  if (this->operator==(v))
    return false;
  else
    return !(this->operator>(v));
}

bool	Variant::operator<=(Variant* v)
{
  if (this->operator<(v) || this->operator==(v))
    return true;
  else
    return false;
}
