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

#include "fatfs.hpp"

void		Fatfs::process()
{
  Node	*tmp;
  try
    {
      //this->ctx = new fsinfo;
      this->root = new Node("Fat File System");
      //this->bootsector->process(this->parent);
      tmp = new bootSectorNode("$bootsector", this, this->root, this->parent, 0x0);
      tmp = new bootSectorNode("$bootsector1", this, this->root, this->parent, 0x200);
      std::cout << "adding two nodes" << std::endl;
      //this->fat->process(this->bootsector);
      this->parent->addChild(this->root);
      //this->bootsector = new bootSector();
    }
  catch(...)
    {
      throw("Fatfs module: error while processing");
    }
  return;
}

void		Fatfs::setContext(argument* arg)
{
  Node	*tmp;
  try
    {
      arg->get("parent", &tmp);
      this->parent = tmp;
    }
  catch(...)
    {
      throw("Fatfs module: error while setting context");
    }
  return;
}

void		Fatfs::start(argument* arg)
{
  try
    {
      this->setContext(arg);
      this->process();
    }
  catch(...)
    {
      throw("Fatfs module: creation of new instance failed");
    }
  return ;
}

Fatfs::~Fatfs()
{
  //delete this->ctx;
}

Fatfs::Fatfs(): mfso("Fat File System")
{
  this->bootsector = new bootSector();
  this->fat = new FileAllocationTable();
}
