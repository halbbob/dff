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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */


#ifndef __ARGUMENT_HPP__
#define __ARGUMENT_HPP__

#ifndef WIN32
#include <stdint.h>
#else
#include "wstdint.h"
#endif

#include <string>
#include <list>
#include <map>

#include "variant.hpp"
#include "export.hpp"

#define TYPEMASK			0x00FF
#define INPUTMASK			0x0300
#define NEEDMASK			0x0C00
#define PARAMMASK			0x3000

// #define OptionalSingleInputWithFixedParam		Optional|SingleInput|FixedParam
// #define OptionalSingleInputWithCustomizableParam	Optional|SingleInput|CustomizableParam
// #define RequiredSingleInputWithFixedParam		Required|SingleInput|FixedParam
// #define RequiredSingleInputWithCustomizableParam	Required|SingleInput|CustomizableParam

// #define OptionalListInputWithFixedParam			Optional|ListInput|FixedParam
// #define OptionalListInputWithCustomizableParam		Optional|ListInput|CustomizableParam
// #define RequiredListInputWithFixedParam			Required|ListInput|FixedParam
// #define RequiredListInputWithCustomizableParam		Required|ListInput|CustomizableParam

struct Parameter
  {
    enum types
    {
      NotEditable = 0x1000,
      Editable = 0x2000
    };
  };

class Argument
{
private:
  std::string			__name;
  uint16_t			__flags;
  std::string			__description;
  bool				__enabled;
  std::list<Variant*>		__parameters;
  bool				__paramslocked;
  void				setParametersType(uint16_t t);

public:
  enum inputTypes
    {
      Empty =			0x0000,
      Single =			0x0100,
      List =			0x0200,
      Optional =		0x0400,
      Required =		0x0800
    };
  Argument(std::string name, uint16_t flags, std::string description = "");
  ~Argument();


  void				addParameters(std::list<Variant*> params, uint16_t type);

  std::list<Variant*>		parameters();
  //void				setName(std::string name);
  std::string			name();

  //void				setFlags(uint16_t flags);
  uint16_t			flags();

  //void				setDescription(std::string description);
  std::string			description();

  //void				setEnabled(bool enabled);
  //bool				isEnabled();

  //void				setType(uint16_t type);
  uint16_t			type();

  //void				setInputType(uint16_t itype);
  uint16_t			inputType();

  uint16_t			parametersType();
  
  //void				setRequirementType(uint16_t ntype);
  uint16_t			requirementType();

  // void				setPreselectedParameters(std::list<Variant* >);
  // std::list<Variant* >		preselectedParameters();

  
  //void				addPredefinedParameters(Variant *params);

  //void				setPreselected();
  //std::list<>			preselected();

  // void				activateParameter(Variant* param);
  // void				deactivateParameter(Variant* param);

  // std::list<Variant*>		predefinedParameters();

  // std::list<Variant*>		activatedParameters();
  // std::list<Variant*>		deactivatedParameters();

  //bool				isRequired();
  //bool				isOptional();
};

#endif
