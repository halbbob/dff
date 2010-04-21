/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __ATTRIBUTES_HPP__
#define __ATTRIBUTES_HPP__

//#include "variant.hpp"
#include "node.hpp"

class ULocalNode: public Node
{
private:
  std::string*			basePath;
public:
  ULocalNode(std::string name, uint64_t size, Node* parent, mfso* fsobj);
  ~ULocalNode();
  void			setBasePath(std::string* bp);
  virtual class FileMapping*	getFileMapping(){}
  virtual class Attributes*	getAttributes();
};

#endif