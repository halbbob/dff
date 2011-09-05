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

#include "fat.hpp"

FileAllocationTableNode::FileAllocationTableNode(std::string name, uint64_t size, Node* parent, class Fatfs* fatfs) : Node(name, size, parent, fatfs)
{
}

FileAllocationTableNode::~FileAllocationTableNode()
{
}

void			FileAllocationTableNode::setContext(FileAllocationTable* fat, uint8_t fatnum)
{
  this->__fat = fat;
  this->__fatnum = fatnum;
}

void			FileAllocationTableNode::fileMapping(FileMapping* fm)
{
  this->__fat->fileMapping(fm, this->__fatnum);
}

Attributes		FileAllocationTableNode::_attributes(void)
{
  return this->__fat->attributes(this->__fatnum);
}


FileAllocationTable::FileAllocationTable()
{
  this->vfile = NULL;
}

// FileAllocationTable::FileAllocationTable(fsinfo* ctx, mfso* fsobj, Node* parent): Decoder("Fat module File Allocation Table reader")
// {
//   this->ctx = ctx;
//   this->fsobj = fsobj;
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

void	FileAllocationTable::setContext(Node* origin, Fatfs* fatfs)
{
  uint8_t	i;
  uint64_t	offset;
  std::stringstream	sstr;
  uint32_t		freeclust;

  this->origin = origin;
  this->fatfs = fatfs;
  this->bs = fatfs->bs;
  try
    {
      this->vfile = this->origin->open();
      if ((this->bs->fatsize < 1024*1024*10) && ((this->__fat = malloc(this->bs->fatsize)) != NULL))
	{
	  offset = this->bs->firstfatoffset + (uint64_t)i * this->bs->fatsize;
	  this->vfile->seek(offset);
	  this->vfile->read(this->__fat, this->bs->fatsize);
	}
      else
	this->__fat = NULL;
      for (uint8_t i = 0; i != this->bs->numfat; i++)
	{
	  sstr << "count free clusters in FAT " << (unsigned char)i;
	  this->fatfs->stateinfo = sstr.str();
	  freeclust = this->freeClustersCount(i);
	  sstr.str("");
	  this->__allocClustCount[i] = this->bs->totalcluster - freeclust;
	  //this->allocatedClustersCount(i);
	}

    }
  catch(vfsError e)
    {
      this->vfile = NULL;
      throw("Fat module: FileAllocationTable error while opening node" + e.error);
    }
}

uint64_t	FileAllocationTable::clusterOffsetInFat(uint64_t cluster, uint8_t which)
{
  uint64_t	baseoffset;
  uint64_t	idx;
  uint64_t	fatsectnum;
  uint64_t	fatentryoffset;

  baseoffset = this->bs->firstfatoffset + (uint64_t)which * (uint64_t)this->bs->fatsize;
  //printf("baseoffset: 0x%llx\n", baseoffset);
  //printf("cluster: %llu\n", cluster);
  if (this->bs->fattype == 12)
    idx = cluster + cluster / 2;
  if (this->bs->fattype == 16)
    idx = cluster * 2;
  if (this->bs->fattype == 32)
    idx = cluster * 4;
  //printf("idx: 0x%llx\n", idx);
  fatsectnum = idx / this->bs->ssize;
  //printf("fatsectnum: 0x%llx\n", fatsectnum);
  fatentryoffset = idx % this->bs->ssize;
  //printf("fatentryoffset: 0x%llx\n", fatentryoffset);
  idx = fatsectnum * this->bs->ssize + fatentryoffset;
  //printf("idx: 0x%llx\n", idx);
  return (baseoffset + idx);
}

uint32_t	FileAllocationTable::ioCluster12(uint32_t current, uint8_t which)
{
  uint16_t	next;
  uint64_t	offset;

  offset = this->clusterOffsetInFat((uint64_t)current, which);
  this->vfile->seek(offset);
  this->vfile->read(&next, 2);
  if (current & 0x0001)
    next = next >> 4;
  else
    next &= 0x0FFF;
  return (uint32_t)next;
}

uint32_t	FileAllocationTable::ioCluster16(uint32_t current, uint8_t which)
{
  uint16_t	next;
  uint64_t	offset;

  offset = this->clusterOffsetInFat((uint64_t)current, which);
  this->vfile->seek(offset);
  this->vfile->read(&next, 2);
  return (uint32_t)next;
}

uint32_t	FileAllocationTable::ioCluster32(uint32_t current, uint8_t which)
{
  uint32_t	next;
  uint64_t	offset;

  offset = this->clusterOffsetInFat((uint64_t)current, which);
  this->vfile->seek(offset);
  this->vfile->read(&next, 4);
  next &= 0x0FFFFFFF;
  return next;
}

uint32_t	FileAllocationTable::cluster12(uint32_t current, uint8_t which)
{
  uint16_t	next;
  uint32_t	idx;

  next = 0;
  if (which < this->bs->numfat)
    {
      if (which == 0 && this->__fat != NULL)
	{
	  idx = current + current / 2;
	  idx = ((idx / this->bs->ssize) * this->bs->ssize) + (idx % this->bs->ssize);
	  memcpy(&next, (uint8_t*)this->__fat+idx, 2);
	}
      else
	next = this->ioCluster12(current, which);
    }
  return (uint32_t)next;
}

uint32_t	FileAllocationTable::cluster16(uint32_t current, uint8_t which)
{
  uint16_t	next;

  next = 0;
  if (which < this->bs->numfat)
    {
      if (which == 0 && this->__fat != NULL)
	next = *((uint16_t*)this->__fat+current);
      else
	next = this->ioCluster16(current, which);
    }
  return (uint32_t)next;
}

uint32_t	FileAllocationTable::cluster32(uint32_t current, uint8_t which)
{
  uint32_t	next;

  next = 0;
  if (which < this->bs->numfat)
    {
      if (which == 0 && this->__fat != NULL)
	{
	  next = *((uint32_t*)this->__fat+current);
	  next &= 0x0FFFFFFF;
	}
      else
	next = this->ioCluster32(current, which);
    }
  return next;
}

uint32_t	FileAllocationTable::nextCluster(uint32_t current, uint8_t which)
{
  uint64_t	offset;
  uint32_t	next;

  next = 0;
  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else if (current > this->bs->totalcluster)
    throw(vfsError(std::string("Fat module: provided cluster is too high")));
  else
    {
      //offset = this->clusterOffsetInFat((uint64_t)current, which);
      //printf("offset for reading cluster: 0x%llx\n", offset);
      if (this->bs->fattype == 12)
	{
	  next = this->cluster12(current, which);
	  //next = this->cluster12(offset, current);
	}
      if (this->bs->fattype == 16)
	{
	  next = this->cluster16(current, which);
	  //next = this->cluster16(offset);
	}
      if (this->bs->fattype == 32)
	{
	  next = this->cluster32(current, which);
	  //next = this->cluster32(offset);
	}
    }
  return next;
}

std::vector<uint64_t>	FileAllocationTable::clusterChainOffsets(uint32_t cluster, uint8_t which)
{
  std::vector<uint64_t>	clustersoffset;
  std::vector<uint32_t>	clusters;
  uint64_t		offset;
  uint32_t		i;

  clusters = this->clusterChain(cluster, which);
  for (i = 0; i != clusters.size(); i++)
    {
      offset = this->clusterToOffset(clusters[i]);
      clustersoffset.push_back(offset);
    }
  return clustersoffset;
}

std::vector<uint32_t>	FileAllocationTable::clusterChain(uint32_t cluster, uint8_t which)
{
  std::vector<uint32_t>	clusters;
  uint64_t		max;
  uint32_t		eoc;

  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else if (cluster > this->bs->totalcluster)
    throw(vfsError(std::string("Fat module: provided cluster is too high")));
  else
    {
      if (this->bs->fattype == 12)
	eoc = 0x0FF8;
      if (this->bs->fattype == 16)
	eoc = 0xFFF8;
      if (this->bs->fattype == 32)
	eoc = 0x0FFFFFF8;
      max = 0;
      while ((cluster < eoc) && (max < 0xFFFFFFFFL))
	{
	  //printf("%d\n", cluster);
	  clusters.push_back(cluster);
	  max += this->bs->csize;
	  try
	    {
	      cluster = this->nextCluster(cluster);
	    }
	  catch(vfsError e)
	    {
	      break;
	    }
	}
    }
  return clusters;
}

/*
/=========================================================\
| For each list*Clusters(uint8_t which), compute a bitmap |
\=========================================================/
*/

bool			FileAllocationTable::isFreeCluster(uint32_t cluster, uint8_t which)
{
  uint32_t		content;
  uint64_t		offset;

  //offset = this->clusterOffsetInFat((uint64_t)cluster, which);
  if (this->bs->fattype == 12)
    content = this->cluster12(cluster, which);
  if (this->bs->fattype == 16)
    content = this->cluster16(cluster, which);
  if (this->bs->fattype == 32)
    content = this->cluster32(cluster, which);
  if (content == 0)
    return true;
  else
    return false;
}

std::vector<uint64_t>	FileAllocationTable::listFreeClustersOffset(uint8_t which)
{
  uint32_t		cidx;
  std::vector<uint64_t>	freeclusters;

  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    for (cidx = 0; cidx != this->bs->totalcluster; cidx++)
      if (this->isFreeCluster(cidx, which))
	freeclusters.push_back(this->clusterToOffset(cidx));
  return freeclusters;
}

std::vector<uint32_t>	FileAllocationTable::listFreeClusters(uint8_t which)
{
  uint32_t		cidx;
  std::vector<uint32_t>	freeclusters;

  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    for (cidx = 0; cidx != this->bs->totalcluster; cidx++)
      if (this->isFreeCluster(cidx, which))
	freeclusters.push_back(cidx);
  return freeclusters;
}

uint32_t		FileAllocationTable::freeClustersCount(uint8_t which)
{
  uint32_t					freeclust;
  uint32_t					cidx;
  std::map<uint32_t, uint32_t>::iterator	it;

  freeclust = 0;
  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    {
      if ((it = this->__freeClustCount.find(which)) != this->__freeClustCount.end())
	freeclust = it->second;
      else
	{
	  for (cidx = 0; cidx != this->bs->totalcluster; cidx++)
	    if (this->isFreeCluster(cidx, which))
	      freeclust++;
	  this->__freeClustCount[which] = freeclust;
	}
    }
    return freeclust;
}

std::list<uint32_t>	FileAllocationTable::listAllocatedClusters(uint8_t which)
{
  std::list<uint32_t>	alloc;

  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    return alloc;
}

uint32_t		FileAllocationTable::allocatedClustersCount(uint8_t which)
{
  uint32_t					cidx;
  uint32_t					alloc;
  std::map<uint32_t, uint32_t>::iterator	it;

  alloc = 0;
  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    {
      if ((it = this->__allocClustCount.find(which)) != this->__allocClustCount.end())
	alloc = it->second;
      else
	{
	  for (cidx = 0; cidx != this->bs->totalcluster; cidx++)
	    if (!this->isFreeCluster(cidx, which))
	      alloc++;
	  this->__allocClustCount[which] = alloc;
	}
    }
  return alloc;
}

std::list<uint32_t>	FileAllocationTable::listBadClusters(uint8_t which)
{
  std::list<uint32_t>	badclust;

  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    return badclust;
}

std::list<uint32_t>	FileAllocationTable::listBadClustersCount(uint8_t which)
{
  std::list<uint32_t>	badclust;

  if (which >= this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    return badclust;
}

uint64_t		FileAllocationTable::clusterToOffset(uint32_t cluster)
{
  uint64_t	offset;

  if (this->bs->fattype == 12)
    cluster &= FATFS_12_MASK;
  if (this->bs->fattype == 16)
    cluster &= FATFS_16_MASK;
  if (this->bs->fattype == 32)
    cluster &= FATFS_32_MASK;
  offset = ((uint64_t)cluster - 2) * this->bs->csize * this->bs->ssize + this->bs->dataoffset;
  return offset;
}

uint32_t		FileAllocationTable::offsetToCluster(uint64_t offset)
{
  //FIXME
  return 0;
}

void			FileAllocationTable::diffFats()
{
}

void			FileAllocationTable::makeNodes(Node* parent)
{
  FileAllocationTableNode*	node;
  std::stringstream		sstr;
  uint64_t			size;
  uint8_t			i;

  for (i = 0; i != this->bs->numfat; i++)
    {
      sstr << "FAT " << i + 1;
      node = new FileAllocationTableNode(sstr.str(), this->bs->fatsize, parent, this->fatfs);
      //this->__fclusterscount.push_back(this->freeClustersCount(i));
      //this->__aclusterscount.push_back(this->allocatedClustersCount(i));
      node->setContext(this, i);
      sstr.str("");
    }
}

void			FileAllocationTable::fileMapping(FileMapping* fm, uint8_t which)
{
  uint64_t		offset;
  
  offset = this->bs->firstfatoffset + (uint64_t)which * (uint64_t)this->bs->fatsize;
  fm->push(0, this->bs->fatsize, this->origin, offset);
}

Attributes			FileAllocationTable::attributes(uint8_t which)
{
  Attributes		attrs;
  
  if (which < this->bs->numfat)
    {
      attrs["free clusters"] = new Variant(this->freeClustersCount(which));
      attrs["allocated clusters"] = new Variant(this->allocatedClustersCount(which));
    }
  return attrs;
}
