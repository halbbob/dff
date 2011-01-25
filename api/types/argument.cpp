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

Argument::Argument(std::string name, uint16_t flags, std::string description)
{
  this->__name = name;
  this->__flags = flags;
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


void				Argument::setFlags(uint16_t flags)
{
  this->__flags = flags;
}

uint16_t			Argument::flags()
{
  return this->__flags;
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

void				Argument::setType(uint16_t type)
{
  this->__flags = (this->__flags&0xFF00)|(type&0x00FF);
}

uint16_t			Argument::type()
{
  return (this->__flags & TYPEMASK);
}

void				Argument::setInputType(uint16_t itype)
{
  this->__flags = (this->__flags&0xFCFF)|(itype&0x0300);
}

uint16_t			Argument::inputType()
{
  return (this->__flags & 0x0300);
}


void				Argument::setParametersType(uint16_t ptype)
{
  this->__flags = (this->__flags&0x0FFF)|(ptype&0xF000);
}

uint16_t			Argument::parametersType()
{
  return (this->__flags & 0xF000);
}

void				Argument::setRequirementType(uint16_t ntype)
{
  this->__flags = (this->__flags&0xF3FF)|(ntype&0x0C00);
}

uint16_t			Argument::requirementType()
{
  return (this->__flags & 0x0c00);
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


// bool			Argument::isOptional()
// {
//   return this->__optional;
// }

// bool			Argument::isMandatory()
// {
//   return !this->__optional;
// }
