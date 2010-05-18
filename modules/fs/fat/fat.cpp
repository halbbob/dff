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

#include "fatreader.hpp"

FileAllocationTable::FileAllocationTable()
{
  this->parent = NULL;
  this->vfile = NULL;
  this->size = 0;
  this->total = 0;
  this->type = 0;
  this->firstfatoffset = 0;
}

// FileAllocationTable::FileAllocationTable(fsinfo* ctx, mfso* fsobj, Node* parent): Decoder("Fat module File Allocation Table reader")
// {
//   this->ctx = ctx;
//   this->fsobj = fsobj;
//   if (parent != NULL)
//     {
//       this->parent = parent;
//       try
// 	{
// 	  this->vfile = this->parent->open();
// 	}
//       catch(vfsError e)
// 	{
// 	  this->vfile = NULL;
// 	  throw("Fat module: FileAllocationTable error while opening node" + e.error);
// 	}
//     }
//   else
//     {
//       this->parent = NULL;
//       this->vfile = NULL;
//     }
// }

FileAllocationTable::~FileAllocationTable()
{
  if (this->vfile != NULL)
    {
      //XXX VFile dtor must close the opened file...
      this->vfile->close();
      delete this->vfile;
    }
}

void		FileAllocationTable::setFirstFatOffset(uint64_t firstfatoffset)
{
  this->firstfatoffset = firstfatoffset;
}

void		FileAllocationTable::setFatType(uint8_t type)
{
  this->type = type;
}

void		FileAllocationTable::setFatSize(uint32_t size)
{
  this->size = size;
}

void		FileAllocationTable::setNumberOfFat(uint8_t total)
{
  this->total = total;
}

uint32_t	FileAllocationTable::getNextCluster(uint32_t current, uint8_t which)
{
  if (which > this->total)
    throw(vfsError(std::string("Fat module: Requested fat number for reading is too high")));
  else
    ;
}

list<uint32_t>	FileAllocationTable::getClusterChain(uint32_t start, uint8_t which)
{
  if (which > this->total)
    throw(vfsError(std::string("Fat module: Requested fat number for reading is too high")));
  else
    ;
}

bool		FileAllocationTable::isRelevant(Node* n)
{
  if (n == this->parent)
    ;
  else
    ;
}

Variant*	FileAllocationTable::getAttributes(Node* n)
{
  if (n == this->parent)
    ;
  else
    ;
}
