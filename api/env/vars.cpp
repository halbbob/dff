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
 *  Frederic B. <fba@digital-forensic.org>
 */

#include "vars.hpp"

Vars::Vars(std::string origin, std::string name, std::string description)
{
  this->__origin = origin;
  this->__name = name;
  this->__description = description;
}

Vars::~Vars()
{
}

std::string	Vars::name()
{
  return this->__name;
}

std::string	Vars::description()
{
  return this->__description;
}

uint8_t		Vars::type()
{
  return this->__type;
}

std::string	Vars::origin()
{
  this->__origin;
}

Variant*	Vars::value()
{
  return this->__value;
}
