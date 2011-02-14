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

#include "confmanager.hpp"

ConfigManager::ConfigManager()
{
}

ConfigManager::~ConfigManager()
{
}

void					ConfigManager::addConf(class Config* c)
{
}

void					ConfigManager::removeConf(std::string origin)
{
}

std::list<class Config*>		ConfigManager::configs()
{
  std::list<class Config*>		lconf;

  return lconf;
}

class Config*				ConfigManager::configByName(std::string confname)
{
  return NULL;
}

std::map<std::string, Constant*>	ConfigManager::constantsByName(std::string constname)
{
  std::map<std::string, Constant*>	mconstants;

  return mconstants;
}

std::map<std::string, Argument*>	ConfigManager::argumentsByName(std::string argname)
{
  std::map<std::string, Argument*>	marguments;

  return marguments;
}
