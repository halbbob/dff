/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: www.digital-forensic.org for more information about this
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

#include <string>
#include <list>
#include <map>
#include <iostream>
#include "export.hpp"
#include "argument.hpp"

class Config
{
private:
  std::string				__origin;
  std::string				__description;
  std::map<std::string, Argument*>	__arguments;

public:
  EXPORT Config(std::string origin, std::string description = "");
  EXPORT ~Config();
  EXPORT std::string		origin();
  EXPORT std::string		description();

  EXPORT void			addArgument(Argument* arg) throw (std::string);
  EXPORT std::list<Argument*>	arguments();
  EXPORT std::list<std::string>	argumentsName();

  EXPORT Argument*		argumentByName(std::string argname);
  EXPORT std::list<Argument*>	argumentsByName(std::list<std::string> argsname);
  EXPORT std::list<Argument*>	argumentsByFlags(uint16_t flags);
  EXPORT std::list<Argument*>	argumentByInputType(uint16_t itype);
  EXPORT std::list<Argument*>	argumentByRequirementType(uint16_t rtype);
  EXPORT std::list<Argument*>	argumentByType(uint16_t type);
};

#endif
