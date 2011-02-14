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


#ifndef __CONFMANAGER_HPP__
#define __CONFMANAGER_HPP__

#include <string>
#include <list>
#include <map>
#include <iostream>
#include "export.hpp"
#include "argument.hpp"
#include "constant.hpp"
#include "config.hpp"

class ConfigManager
{
private:
  std::map<std::string, class Config*>	__configs;
  EXPORT ConfigManager();
  EXPORT ~ConfigManager();
  ConfigManager&          operator=(ConfigManager&);
  ConfigManager(const ConfigManager&);
  
public:
  static ConfigManager   *Get()
  {
    static ConfigManager single;
    return &single;
  }
  void					addConf(class Config* c);
  void					removeConf(std::string origin);
  std::list<class Config*>		configs();
  class Config*				configByName(std::string confname);
  std::map<std::string, Constant*>	constantsByName(std::string constname);
  std::map<std::string, Argument*>	argumentsByName(std::string argname);
};

#endif
