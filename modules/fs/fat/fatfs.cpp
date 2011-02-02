/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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
      if (this->parent->size() > 0)
	{
	  this->vfile = this->parent->open();
	  this->bs->process(this->parent, this);
	  this->fat->setContext(this->parent, this->bs);
	  this->root = new Node("Fat File System", 0, NULL, this);
	  this->root->setDir();
	  this->tree->process(this->parent, this, this->root);
	}
    }
  catch(...)
    {
      throw("Fatfs module: error while processing");
    }
  return;
}

void		Fatfs::setContext(argument* arg)
{
  try
    {
      arg->get("file", &(this->parent));
    }
  catch(envError e)
    {
      throw(envError("Fatfs module: error while setting context"));
    }
  try
    {
      arg->get("meta_carve", &this->carveunalloc);
    }
  catch(envError e)
    {
      this->carveunalloc = false;
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
      return;
      //throw(vfsError("Fatfs module: creation of new instance failed"));
    }
  return ;
}

Fatfs::~Fatfs()
{
  //delete this->ctx;
}

Fatfs::Fatfs(): mfso("Fat File System")
{
  this->bs = new BootSector();
  this->fat = new FileAllocationTable();
  this->tree = new FatTree();
}
