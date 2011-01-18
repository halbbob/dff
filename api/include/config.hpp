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


#ifndef __CONFIG_HPP__
#define __CONFIG_HPP__

#include "variant.hpp"
#include <string>
#include <list>
#include <map>
#include <iostream>
#include "export.hpp"

#define ParamUnique		0x01
#define ParamList		0x02
#define ParamVariable		ParamUnique | ParamList
//#define ParamRange		0x04 <-- later use
#define ParamOptional		0x05
#define ParamMandatory		0x09

#define UniqueAndOptional	ParamUnique | ParamOptional
#define UniqueAndMandatory	ParamUnique | ParamMandatory
#define ListAndOptional		ParamList | ParamOptional
#define ListAndMandatory	ParamList | ParamMandatory
//#define VariableAndOptional	ParamVariable | ParamOptional
//#define VariableAndMandatory	ParamVariable | ParamMandatory

#define DefaultFixed		0x01
#define DefaultSuggested	0x02

class Parameter
{
private:
  uint8_t		__type;
  bool			__optional;
  std::string		__description;
  std::list<Variant* >	__defaults;
public:
  Parameter(uint8_t type, bool optional, std::string description);
  ~Parameter();
  uint8_t		type();
  bool			isMandatory();
  bool			isOptional();
  std::string		description();
  void			addDefault(Variant* val);
  std::list<Variant* >	defaults();
};

class Config
{
private:
  std::string				__origin;
  std::string				__description;
  std::map<std::string, Parameter* >	__parameters;

public:
  EXPORT Config(std::string origin, std::string description = "");
  EXPORT ~Config();
  EXPORT void					add(std::string param, uint8_t type, bool optional=false, std::string description = "");
  EXPORT void					add_const(std::string param, Variant* val);

  EXPORT std::string				origin();
  EXPORT std::string				description();
  EXPORT std::map<std::string, Parameter*>	parameters();
};

#endif
