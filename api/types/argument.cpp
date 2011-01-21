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
 *  Frederic B. <fba@digital-forensic.org>
 */


#include "argument.hpp"

Argument::Argument(std::string name, uint16_t type, std::string description)
{
  this->__name = name;
  this->__type = type;
  this->__description = description;
}

Argument::~Argument()
{
}

void				Argument::setName(std::string name)
{
  this->__name = name;
}

std::string			Argument::name()
{
  return this->__name;
}


void				Argument::setType(uint16_t type)
{
  this->__type = type;
}

uint16_t			Argument::type()
{
  return (this->__type & TYPEMASK);
}


void				Argument::setDescription(std::string description)
{
  this->__description = description;
}

std::string			Argument::description()
{
  return this->__description;
}

void				Argument::setEnabled(bool enabled)
{
  this->__enabled = enabled;
}

bool				Argument::isEnabled()
{
  return this->__enabled;
}



// void				Argument::addPredefinedParameters(Variant* param)
// {
//   std::cout << "Adding new param to " << this->__name << std::endl;
//   //this->__predefparams.insert(std::pair<Variant*, bool>(param, true));
//   this->__predefparams.push_back(param);
// }

// void				Argument::activateParameter(Variant* param)
// {
  
// }

// void				Argument::deactivateParameter(Variant* param)
// {
// }




// std::list<Variant*>		Argument::predefinedParameters()
// {
//   return this->__predefparams;
// }

// std::list<Variant*>	Argument::activatedParameters()
// {
// }

// std::list<Variant*>	Argument::deactivatedParameters()
// {
// }


uint16_t			Argument::inputType()
{
  
}

uint16_t			Argument::parametersType()
{
}

uint16_t			Argument::needType()
{
}

// bool			Argument::isOptional()
// {
//   return this->__optional;
// }

// bool			Argument::isMandatory()
// {
//   return !this->__optional;
// }
