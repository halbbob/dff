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
 */

#ifndef __VARS_HPP__
#define __VARS_HPP__

#include "variant.hpp"
#include "export.hpp"
#include "type.hpp"
#include <string>
#include <iostream>
#include <list>
#ifndef WIN32
#include <stdint.h>
#else
#include "wstdint.h"
#endif

//config
// - Global for module
// - needs
//   - name
//   - description
//   - origin
//   - optional
//   - type
//   - defaults
//
//argument
// - for each module instance
// - needs:
//   - name
//   - variant
//
//results
// - for each module instance
// - needs:
//  - name
//  - description
//  - variant

class ConfigVar
{
private:
  std::string		__name;
  std::string		__description;
  std::string		__origin;
  uint8_t		__type;
  bool			__optional;
public:
  std::string		name();
  std::string		description();
  std::string		origin();
  uint8_t		type();
  bool			isOptional();
};

class Vars
{
private:
  std::string		__name;
  std::string		__description;
  std::string		__origin;
  Variant*		__var;

public:
  Vars(std::string origin, std::string name, std::string description);
  ~Vars();
  std::string	name();
  std::string	description();
  uint8_t	type();
  std::string	origin();
  Variant*	value();
};

// class Vars
// {
// private:
//   std::string		__name;
//   std::string		__description;
//   uint8_t		__type;
//   std::string		__origin;
//   bool			__optional;
//   Variant*		__value;
//   std::list<Variant*>	__defaults;


// public:
//   Vars(std::string origin, std::string name, bool optional, std::string description, uint8_t type);
//   ~Vars();
//   bool		addDefault(Variant* defaults);
//   std::list<Variant*>	defaults();
//   std::string	name();
//   std::string	description();
//   uint8_t	type();
//   std::string	origin();
//   bool		isOptional();
//   Variant*	value();
// };

#endif
