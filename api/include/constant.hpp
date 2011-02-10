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

#ifndef __CONSTANT_HPP__
#define __CONSTANT_HPP__

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

class Constant
{
private:
  std::string		__name;
  uint8_t		__type;
  std::string		__description;
  bool			__valueslocked;
  std::list<Variant*>	__values;

public:
  Constant(std::string name, uint8_t type, std::string description);
  ~Constant();
  std::string		name();
  std::string		description();
  uint8_t		type();
  void			addValues(std::list<Variant*> values);
  std::list<Variant*>	values();    
};

#endif
