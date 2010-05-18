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
#include "decoder.hpp"
#include "node.hpp"

class UMetadata: public Metadata
{
private:
  std::string			basePath;
public:
  UMetadata();
  ~UMetadata();
  void				setBasePath(std::string bp);
  virtual class FileMapping*	getFileMapping(class Node* node){}
  virtual class Attributes*	getAttributes(class Node* node);
};

#endif
