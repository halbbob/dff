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

#ifndef __RESULTS_HPP__
#define __RESULTS_HPP__

#include <string>
#include <list>
#include <map>
//#include "env.hpp"
#include "variant.hpp"
#include "export.hpp"

class Results
{
private:
  std::string				__origin;
  //std::map<std::string, dresult* >	__results;
public:
  EXPORT Results(std::string origin);
  EXPORT ~Results();
  EXPORT bool					add(std::string name, Variant* val, std::string description);
  EXPORT Variant*				valueFromKey(std::string name);
  EXPORT std::string				descriptionFromKey(std::string);
  EXPORT std::map<std::string, Variant*>	items();
  EXPORT std::list<std::string>			keys();
  EXPORT std::list<Variant*>			values();
};

#endif
