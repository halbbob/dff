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

<<<<<<< HEAD
#include "node.hpp"
=======
#include "filemapping.hpp"
>>>>>>> !!! STILL VERY EXPERIMENTAL BRANCH !!!

FileMapping::FileMapping()
{
  this->__mappedFileSize = 0;
  this->__prevChunck = NULL;
}

FileMapping::~FileMapping()
{
  uint32_t	i;

  for (i = 0; i != this->__chuncks.size(); i++)
    delete this->__chuncks[i];
}

uint32_t		FileMapping::chunckCount()
{
  return this->__chuncks.size();
}

chunck*			FileMapping::chunckFromIdx(uint32_t idx)
{
  if (idx < this->__chuncks.size())
    return this->__chuncks[idx];
  else
    return NULL;
}

std::vector<chunck *>	FileMapping::chuncksFromIdxRange(uint32_t begidx, uint32_t endidx)
{
  std::vector<chunck *>	v;
  uint32_t		vsize;
  std::vector<chunck *>::iterator	begit;
  std::vector<chunck *>::iterator	endit;
  
  vsize = this->__chuncks.size();
  if ((begidx < endidx) && (begidx < vsize) && (endidx < vsize))
    {
      begit = this->__chuncks.begin()+begidx;
      endit = this->__chuncks.begin()+endidx;
      v.assign(begit, endit);
    }
  return v;
}

std::vector<chunck *>	FileMapping::chuncksFromOffsetRange(uint64_t begoffset, uint64_t endoffset)
{
  std::vector<chunck *>	v;
  uint32_t		begidx;
  uint32_t		endidx;

  if ((begoffset > endoffset) || (begoffset > this->__mappedFileSize) || (endoffset > this->__mappedFileSize))
    throw("provided offset too high");
  try
    {
      begidx = this->chunckIdxFromOffset(begoffset);
      endidx = this->chunckIdxFromOffset(endoffset);
      v = this->chuncksFromIdxRange(begidx, endidx);
    }
  catch (...)
    {
    }
  return v;
}

chunck*			FileMapping::firstChunck()
{
  if (this->__chuncks.size() > 0)
    return this->__chuncks.front();
  else
    return NULL;
}

chunck*			FileMapping::lastChunck()
{
  if (this->__chuncks.size() > 0)
    return this->__chuncks.back();
  else
    return NULL;
}


std::vector<chunck *>	FileMapping::chuncks()
{
  return this->__chuncks;
}

chunck*			FileMapping::chunckFromOffset(uint64_t offset)
{
  uint32_t		begidx;
  uint32_t		mididx;
  uint32_t		endidx;
  
  if (offset > this->__mappedFileSize)
    throw("provided offset too high");
  if (this->__chuncks.size() == 0)
    throw("not found");
  else if (this->__chuncks.size() == 1)
    return this->__chuncks[0];
  else
    {
      begidx = 0;
      mididx = this->__chuncks.size() / 2;
      endidx = this->__chuncks.size();
      while (true)
	{
	  if ((offset >= this->__chuncks[mididx]->offset) && (offset < (this->__chuncks[mididx]->offset + this->__chuncks[mididx]->size)))
	    return this->__chuncks[mididx];
	  else if (offset < this->__chuncks[mididx]->offset)
	    endidx = mididx;
	  else
	    begidx = mididx;
	  mididx = begidx + ((endidx - begidx) / 2);
	}
    }
}
<<<<<<< HEAD
=======

>>>>>>> !!! STILL VERY EXPERIMENTAL BRANCH !!!
uint32_t	FileMapping::chunckIdxFromOffset(uint64_t offset, uint32_t providedidx)
{
  uint32_t		begidx;
  uint32_t		mididx;
  uint32_t		endidx;
  
  if (offset > this->__mappedFileSize)
    throw("provided offset too high");
  if (this->__chuncks.size() == 0)
    throw("not found");
  else if (this->__chuncks.size() == 1)
    return 0;
  else
    {
      begidx = providedidx;
      endidx = this->__chuncks.size();
      mididx = begidx + ((endidx - begidx) / 2);
      while (true)
	{
// 	  std::cout << "begidx: " << begidx << " mididx: " << mididx << " endidx: " << endidx
// 		    << " offset: " << offset << " mididx->offset: " << this->__chuncks[mididx]->offset << std::endl;
	  if ((offset >= this->__chuncks[mididx]->offset) && (offset < (this->__chuncks[mididx]->offset + this->__chuncks[mididx]->size)))
	    return mididx;
	  else if (offset < this->__chuncks[mididx]->offset)
	    endidx = mididx;
	  else
	    begidx = mididx;
	  mididx = begidx + ((endidx - begidx) / 2);
	}
    }
}

<<<<<<< HEAD
=======

>>>>>>> !!! STILL VERY EXPERIMENTAL BRANCH !!!
void		FileMapping::allocChunck(uint64_t offset, uint64_t size, class Node* origin, uint64_t originoffset)
{
  chunck	*c;

  c = new chunck;
  c->offset = offset;
  c->size = size;
  this->__mappedFileSize += size;
  c->origin = origin;
  c->originoffset = originoffset;
  this->__chuncks.push_back(c);
  this->__prevChunck = c;
}

//XXX Do some sanity checks:
// origin != NULL
// originoffset < origin.size
// originoffset + size < origin.size
// 
// Manage pushed chunck on the fly to check if current push is contiguous with prev chunck
//  if (origin == prev_chunck->origin) and (originoffset == prev_chunck->offset + prev_chunck->size)
//    prev_chunck->size += size
// if origin and originoffset not provided, the chunck is seen as shadow:
//  - reading on this kind of chunck will provide a buffer filled with 0
void			FileMapping::push(uint64_t offset, uint64_t size, class Node* origin, uint64_t originoffset)
{
	//if (origin != NULL)
	//if (this->__prevChunck != NULL)
	//if ((origin == this->__prevChunck->origin) && (originoffset == (this->__prevChunck->offset + this->__prevChunck->size)))
	//{
	//this->__prevChunck->size += size;
	//this->__mappedFileSize += size;
	//}
	//else
	//this->allocChunck(offset, size, origin, originoffset);
	//else
	//this->allocChunck(offset, size, origin, originoffset);
	//else
    this->allocChunck(offset, size, origin, originoffset);
}


uint64_t	FileMapping::mappedFileSize()
{
  return this->__mappedFileSize;
}
