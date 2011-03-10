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

#ifndef __DATATYPE_HPP__
#define __DATATYPE_HPP__

#include "variant.hpp"
#include "node.hpp"
#include <list>


class DataTypeHandler
{
public:
  EXPORT		DataTypeHandler(std::string);
  EXPORT  virtual 	~DataTypeHandler();
  EXPORT  virtual	std::string* type(class Node*) = 0;
  std::string		name;
}; 

class DataTypeManager 
{
private:
  EXPORT					DataTypeManager();
  EXPORT					~DataTypeManager();
  DataTypeManager&				operator=(DataTypeManager&);
  						DataTypeManager(const DataTypeManager&);
  list<DataTypeHandler*>			handlers;
  uint32_t					idCounter;
  std::map<Node*, std::vector< uint32_t > >	nodeTypeId;
  std::map<std::string, uint32_t >		uniq; 
  std::map<uint32_t, std::string>		typeIdString;
  std::map<uint32_t, DataTypeHandler*>		typeIdHandler; 
public:
  EXPORT static DataTypeManager* 	Get();
  EXPORT bool						registerHandler(DataTypeHandler*);
  EXPORT std::map<std::string, uint32_t>&		foundTypes();
  EXPORT class Variant*				type(Node*);
};

#endif
