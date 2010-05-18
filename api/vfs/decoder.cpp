/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include "decoder.hpp"

FileMapping::FileMapping()
{
}

FileMapping::~FileMapping()
{
}

chunck*			FileMapping::getNextChunck()
{
}

chunck*			FileMapping::getPrevChunck()
{
}

std::vector<chunck *>	FileMapping::getChuncks()
{
}

void			FileMapping::push(class Node* from, uint64_t start, uint64_t end)
{
}

Attributes::Attributes()
{
  this->attrs = new std::map<std::string, class Variant*>;
}

Attributes::~Attributes()
{
  delete this->attrs;
}

void					Attributes::push(std::string key, class Variant *value)
{
  if (value != NULL)
    this->attrs->insert(pair<std::string, class Variant*>(key, value));
}

std::list<std::string>			Attributes::getKeys()
{
  std::list<std::string>		keys;
  std::map<std::string, class Variant*>::iterator it;

  for (it = this->attrs->begin(); it != this->attrs->end(); it++)
    keys.push_back(it->first);
  return keys;
}

Variant*				Attributes::getValue(std::string key)
{
  std::map<std::string, class Variant*>::iterator it;

  it = this->attrs->find(key);
  if (it != this->attrs->end())
    return (it->second);
  else
    return NULL;
}

std::map<std::string, class Variant*>*	Attributes::get()
{
  return this->attrs;
}
