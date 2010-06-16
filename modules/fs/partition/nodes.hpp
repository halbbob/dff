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

#ifndef __NODES_HPP__
#define __NODES_HPP__

#include "node.hpp"

class PartitionNode: public Node
{
private:
  uint64_t	start;
  Node*		origin;
public:
  PartitionNode(std::string name, uint64_t size, Node* parent, mfso* fsobj, Node* origin, uint64_t start);
  ~PartitionNode();
  virtual class FileMapping*	fileMapping();
  virtual class Attributes*	attributes();
};

// class EntryNode: public Node
// {
// public:
//   EntryNode(std::string name, Node* parent, mfso* fsobj, Node* origin);
//   ~EntryNode();
//   virtual class FileMapping*	getFileMapping();
//   virtual class Attributes*	getAttributes();
// };

// class RecordNode: public Node
// {
// public:
//   RecordNode(std::string name, Node* parent, mfso* fsobj, Node* origin);
//   ~RecordNode();
//   virtual class FileMapping*	getFileMapping();
//   virtual class Attributes*	getAttributes();
// };

#endif 
