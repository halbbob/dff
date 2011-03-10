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
 */

#include "datatype.hpp"

DataTypeManager* 	DataTypeManager::Get()
{
  static DataTypeManager single;
  return &single;
}

DataTypeManager::DataTypeManager()
{
  idCounter = 0;
}

DataTypeManager::~DataTypeManager()
{
}

bool		DataTypeManager::registerHandler(DataTypeHandler* handler)
{
  this->handlers.push_back(handler);
  return true;
}

Variant*	DataTypeManager::type(Node* node)
{
  std::list<DataTypeHandler* >::iterator	handler;
  std::map<std::string, Variant *>		vars;

  if ((this->nodeTypeId[node].empty()))
  {
    if (!(this->handlers.empty()))
    {
      for (handler = this->handlers.begin(); handler != this->handlers.end(); handler++)
      {
        std::string* res = (*handler)->type(node);
	uint32_t id = uniq[*res];
	if (id)
	 nodeTypeId[node].push_back(id);
        else
	{
	  uniq[*res] = ++idCounter;
	  typeIdString[idCounter] = *res;
          typeIdHandler[idCounter] = *handler;
	  nodeTypeId[node].push_back(idCounter);
        }
      } 
    }
  }
  std::vector<uint32_t>::iterator it = nodeTypeId[node].begin();
  std::vector<uint32_t>::iterator end = nodeTypeId[node].end();
  for (; it != end; it++)
    vars[typeIdHandler[*it]->name] = new Variant(typeIdString[*it]);
   
  Variant* var	= new Variant(vars);

  return var;
}

std::map<std::string, uint32_t>&	DataTypeManager::foundTypes()
{
  return (this->uniq);
}

DataTypeHandler::DataTypeHandler(std::string hname)
{
  DataTypeManager* 	dataTypeManager =  DataTypeManager::Get();

  this->name = hname;
  dataTypeManager->registerHandler(this);
}

DataTypeHandler::~DataTypeHandler()
{

}

