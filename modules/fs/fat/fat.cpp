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

#include "fat.hpp"

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

void	FileAllocationTable::setContext(Node* origin, BootSector* bs)
{
  this->origin = origin;
  this->bs = bs;
  try
    {
      this->vfile = this->origin->open();
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

uint32_t	FileAllocationTable::cluster12(uint64_t offset, uint32_t current)
{
  uint16_t	next;

  this->vfile->seek(offset);
  this->vfile->read(&next, 2);
  if (current & 0x0001)
    next = next >> 4;
  else
    next &= 0x0FFF;
  return (uint32_t)next;
}

uint32_t	FileAllocationTable::cluster16(uint64_t offset)
{
  uint16_t	next;

  this->vfile->seek(offset);
  this->vfile->read(&next, 2);
  next &= 0xFFFF;
  return (uint32_t)next;
}

uint32_t	FileAllocationTable::cluster32(uint64_t offset)
{
  uint32_t	next;

  this->vfile->seek(offset);
  next = 0x0FFFFFF8;
  this->vfile->read(&next, 4);
  next &= 0x0FFFFFFF;
  return next;
}

uint32_t	FileAllocationTable::nextCluster(uint32_t current, uint8_t which)
{
  uint64_t	offset;
  uint32_t	next;

  next = 0;
  if (which > this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else if (current > this->bs->totalcluster)
    throw(vfsError(std::string("Fat module: provided cluster is too high")));
  else
    {
      offset = this->clusterOffsetInFat((uint64_t)current, which);
      //printf("offset for reading cluster: 0x%llx\n", offset);
      if (this->bs->fattype == 12)
	next = this->cluster12(offset, current);
      if (this->bs->fattype == 16)
	next = this->cluster16(offset);
      if (this->bs->fattype == 32)
	next = this->cluster32(offset);
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

  if (which > this->bs->numfat)
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

  offset = this->clusterOffsetInFat((uint64_t)cluster, which);
  if (this->bs->fattype == 12)
    content = this->cluster12(offset, cluster);
  if (this->bs->fattype == 16)
    content = this->cluster16(offset);
  if (this->bs->fattype == 32)
    content = this->cluster32(offset);
  if (content == 0)
    return true;
  else
    return false;
}

std::vector<uint64_t>	FileAllocationTable::listFreeClustersOffset(uint8_t which)
{
  uint32_t		cidx;
  std::vector<uint64_t>	freeclusters;

  if (which > this->bs->numfat)
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

  if (which > this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    for (cidx = 0; cidx != this->bs->totalcluster; cidx++)
      if (this->isFreeCluster(cidx, which))
	freeclusters.push_back(cidx);
  return freeclusters;
}

uint32_t		FileAllocationTable::freeClustersCount(uint8_t which)
{
  if (which > this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    ;
}

std::list<uint32_t>	FileAllocationTable::listAllocatedClusters(uint8_t which)
{
  if (which > this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    ;
}

uint32_t		FileAllocationTable::allocatedClustersCount(uint8_t which)
{
  if (which > this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    ;
}

std::list<uint32_t>	FileAllocationTable::listBadClusters(uint8_t which)
{
  if (which > this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    ;
}

std::list<uint32_t>	FileAllocationTable::listBadClustersCount(uint8_t which)
{
  if (which > this->bs->numfat)
    throw(vfsError(std::string("Fat module: provided fat number for reading is too high")));
  else
    ;
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
}

void			FileAllocationTable::diffFats()
{
}
