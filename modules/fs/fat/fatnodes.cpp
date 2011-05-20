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

#include "fatnodes.hpp"


FatNode::FatNode(std::string name, uint64_t size, Node* parent, class Fatfs* fs): Node(name, size, parent, fs)
{
  this->fs = fs;
}

FatNode::~FatNode()
{
}

vtime*	FatNode::dosToVtime(uint16_t dos_time, uint16_t dos_date)
{
  vtime*	vt;

  vt = new vtime();
  vt->day = (dos_date & 31);
  vt->month = ((dos_date >> 5) & 15);
  vt->year = ((dos_date >> 9) + 1980);

  if (dos_time != 0)
    {
      vt->second = (dos_time & 31) * 2;
      vt->minute = ((dos_time >> 5) & 63);
      vt->hour = (dos_time >> 11);
    }
  else
    {
      vt->second = 0;
      vt->minute = 0;
      vt->hour = 0;
    }
  return vt;
}


void		FatNode::setLfnMetaOffset(uint64_t lfnmetaoffset)
{
  this->lfnmetaoffset = lfnmetaoffset;
}

void		FatNode::setDosMetaOffset(uint64_t dosmetaoffset)
{
  this->dosmetaoffset = dosmetaoffset;
}

void		FatNode::setCluster(uint32_t cluster, bool reallocated)
{
  this->__clustrealloc = reallocated;
  this->cluster = cluster;
}

void		FatNode::fileMapping(FileMapping* fm)
{
  std::vector<uint64_t>	clusters;
  unsigned int		i;
  uint64_t		voffset;
  uint64_t		clustsize;
  uint64_t		rsize;

  voffset = 0;
  rsize = this->size();
  clustsize = this->fs->bs->csize * this->fs->bs->ssize;
  if (!this->__clustrealloc)
    {
      clusters = this->fs->fat->clusterChainOffsets(this->cluster);
      if ((clusters.size() * clustsize) < this->size())
	{
	  uint64_t	firstclustoff = this->fs->fat->clusterToOffset(this->cluster);
	  fm->push(0, rsize, this->fs->parent, firstclustoff);
	}
      else
	{
	  for (i = 0; i != clusters.size(); i++)
	    {
	      if (rsize < clustsize)
		fm->push(voffset, rsize, this->fs->parent, clusters[i]);
	      else
		fm->push(voffset, clustsize, this->fs->parent, clusters[i]);
	      rsize -= clustsize;
	      voffset += clustsize;
	    }
	}
    }
  else
    fm->push(0, this->size());
}



Attributes	FatNode::_attributes()
{
  Attributes	attr;
  VFile*	vf;
  std::vector<uint32_t>	clusters;
  //std::list<Variant*>	clustlist;
  unsigned int			i;
  uint8_t*			entry;
  EntriesManager*		em;
  dosentry*			dos;

  em = new EntriesManager(this->fs->bs->fattype);
  vf = this->fs->parent->open();
  attr["lfn entries start offset"] =  new Variant(this->lfnmetaoffset);
  attr["dos entry offset"] = new Variant(this->dosmetaoffset);
  if ((entry = (uint8_t*)malloc(sizeof(dosentry))) != NULL)
    {
      vf->seek(this->dosmetaoffset);
      vf->read(entry, sizeof(dosentry));
      vf->close();
      dos = em->toDos(entry);
      free(entry);
      attr["modified"] = new Variant(this->dosToVtime(dos->mtime, dos->mdate));
      attr["accessed"] = new Variant(this->dosToVtime(0, dos->adate));
      attr["changed"] = new Variant(this->dosToVtime(dos->ctime, dos->cdate));
      attr["dos name (8+3)"] = new Variant(em->formatDosname(dos));
      delete em;
      attr["Read Only"] = new Variant(bool(dos->attributes & ATTR_READ_ONLY));
      attr["Hidden"] = new Variant(bool(dos->attributes & ATTR_HIDDEN));
      attr["System"] = new Variant(bool(dos->attributes & ATTR_SYSTEM));
      attr["Archive"] = new Variant(bool(dos->attributes & ATTR_ARCHIVE));
      attr["Volume"] = new Variant(bool(dos->attributes & ATTR_VOLUME));  
      delete dos;
      try
	{
	  uint64_t clustsize = this->fs->bs->csize * this->fs->bs->ssize;
	  if (this->__clustrealloc)
	    attr["first cluster (!! reallocated to another existing entry)"] = new Variant(this->cluster);
	  else
	    {
	      if ((!this->isDeleted()) && (this->size()) && (this->size() % clustsize))
		{
		  std::map<std::string, Variant*>	slackinfo;
		  clusters = this->fs->fat->clusterChain(this->cluster);
		  uint32_t	lastclust = clusters.back();
		  uint64_t	ssize = (((uint64_t)clusters.size()) * clustsize) - this->size();
		  uint64_t	soffset = this->fs->fat->clusterToOffset(lastclust);
		  slackinfo["start offset"] = new Variant(soffset + clustsize - ssize);
		  slackinfo["size"] = new Variant(ssize);
		  attr["slack space"] = new Variant(slackinfo);	      
		}
	      //for (i = 0; i != clusters.size(); i++)
	      //clustlist.push_back(new Variant(clusters[i]));
	      attr["first cluster"] = new Variant(this->cluster);
	      //attr["allocated clusters"] = new Variant(clustlist);
	    }
	}
      catch(vfsError e)
	{
	  return attr;
	}
    }
  return attr;
}
