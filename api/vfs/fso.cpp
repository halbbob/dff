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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include "fso.hpp"

fso::fso(std::string name)
{
  this->name = name;
  //this->res = new Results(this->name);
  this->stateinfo = "";
}

fso::~fso()
{
}

std::list<Node *>	fso::updateQueue()
{
  return this->__update_queue;
}

void	fso::registerTree(Node* parent, Node* head)
{
  event*  e = new event;
  e->value = new Variant(head);

  parent->addChild(head);
  VFS::Get().notify(e);
}
