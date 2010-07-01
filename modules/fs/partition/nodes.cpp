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

#include "nodes.hpp"

PartitionNode::PartitionNode(std::string name, uint64_t size, Node* parent, mfso* fsobj, Node* origin, uint64_t start):  Node(name, size, parent, fsobj)
{
  this->origin = origin;
  this->start = start;
  this->setFile();
}

PartitionNode::~PartitionNode()
{
}

void	PartitionNode::fileMapping(FileMapping* fm)
{
  fm->push(0, this->size(), this->origin, this->start);
}

// EntryNode::EntryNode(std::string name, Node* parent, mfso* fsobj, Node* origin): Node(name, 0x10, parent, fsobj)
// {
// }

// EntryNode::~EntryNode()
// {
// }

// FileMapping*	EntryNode::getFileMapping()
// {
// }

// Attributes*	EntryNode::getAttributes()
// {
// }


// RecordNode::RecordNode(std::string name, Node* parent, mfso* fsobj, Node* origin):Node(name, 0x200, parent, fsobj)
// {
// }

// RecordNode::~RecordNode()
// {
// }

// FileMapping*	RecordNode::getFileMapping()
// {
// }

// Attributes*	RecordNode::getAttributes()
// {
// }
