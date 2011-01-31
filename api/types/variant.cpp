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

typeId *typeId::_instance = 0;

typeId::typeId()
{
  this->mapping.insert(std::pair<char*, uint8_t>( (char*)typeid(int16_t*).name(), typeId::Int16));
  this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(uint16_t*).name(), typeId::UInt16));
  this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(int32_t*).name(), typeId::Int32));
  this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(uint32_t*).name(), typeId::UInt32));
  this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(int64_t*).name(), typeId::Int64));
  this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(uint64_t*).name(), typeId::UInt64));
  this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(char*).name(), typeId::Char));
  this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(char**).name(), typeId::CArray));
  this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(void**).name(), typeId::VoidStar));
  this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(std::string *).name(), typeId::String));
  this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(class vtime**).name(), typeId::VTime));
  this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(class Node**).name(), typeId::Node));
  this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(class Path**).name(), typeId::Path));
  this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(std::map<std::string, class Variant*> *).name(), typeId::Map));
  this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(std::list<class Variant*> *).name(), typeId::List));
  //this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(std::vector<class Variant*> *).name(), typeId::List));
  //this->mapping.insert(std::pair<char*, uint8_t>((char*)typeid(std::set<class Variant*> *).name(), typeId::List));
}

typeId::~typeId()
{
  //  delete this->mapping;
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
  this->__data.ptr = (void*)(new std::string(str));
  this->_type = typeId::String;
}

Variant::Variant(char *carray)
{
  this->__data.ptr = (void*)carray;
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
  this->_type = typeId::Int16;
}

Variant::Variant(uint16_t us)
{
  this->__data.us = us;
  this->_type = typeId::UInt16;
}

Variant::Variant(int32_t i)
{
  this->__data.i = i;
  this->_type = typeId::Int32;
}

Variant::Variant(uint32_t ui)
{
  this->__data.ui = ui;
  this->_type = typeId::UInt32;
}

Variant::Variant(int64_t ll)
{
  this->__data.ll = ll;
  this->_type = typeId::Int64;
}

Variant::Variant(uint64_t ull)
{
  this->__data.ull = ull;
  this->_type = typeId::UInt64;
}

Variant::Variant(vtime *vt)
{
  this->__data.ptr = (void*)vt;
  this->_type = typeId::VTime;
}

Variant::Variant(class Node *node)
{
  this->__data.ptr = node;
  this->_type = typeId::Node;
}

Variant::Variant(Path *path)
{
  this->__data.ptr = path;
  this->_type = typeId::Path;
}

Variant::Variant(std::list<Variant*> l)
{
  this->__data.ptr = (void*)new std::list<Variant*>(l);
  this->_type = typeId::List;
}

Variant::Variant(std::map<std::string, Variant*> m)
{
  this->__data.ptr = (void*)new std::map<std::string, Variant *>(m);
  this->_type = typeId::Map;
}

Variant::Variant(void *user)
{
  this->__data.ptr = (void*)user;
  this->_type = typeId::VoidStar;
}

// bool	Variant::operator==(Variant* v)
// {
//   std::cout << "operator == Variant*" << std::endl;
//   this->operator==(v->value<int16_t>());
// }

// bool  Variant::operator==(Variant* v)
// {
//   if (v->value() == this->value())
//     std::cout << "operator== for variant" << std::endl;
//   return true;
// }

// bool	Variant::operator==(std::map<std::string, Variant* > *m)
// {
//   std::cout << "operator== for map of variant\n" << std::endl;
//   return true;
// }

// bool	Variant::operator==(std::list<Variant* > *l)
// {
//   std::cout << "operator== for list of variant\n" << std::endl;
//   return true;
// }


std::string	Variant::toString()
{
    //FIXME
	return std::string();
}

uint16_t	Variant::toUInt16()
{
	//FIXME
	return 0;
}

int16_t		Variant::toInt16()
{
	//FIXME
	return 0;
}

uint32_t	Variant::toUInt32()
{
	//FIXME
	return 0;
}

int32_t		Variant::toInt32()
{
	//FIXME
	return 0;
}

uint64_t	Variant::toUInt64()
{
	//FIXME
	return 0;
}

int64_t		Variant::toInt64()
{
	//FIXME
	return 0;
}

bool		Variant::toBool()
{
	//FIXME
	return true;
}

uint8_t		Variant::type()
{
  return this->_type;
}
