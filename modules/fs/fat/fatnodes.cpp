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

void	FatNode::dosToVtime(vtime* vt, uint16_t dos_time, uint16_t dos_date)
{
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
}


void		FatNode::setLfnMetaOffset(uint64_t lfnmetaoffset)
{
  this->lfnmetaoffset = lfnmetaoffset;
}

void		FatNode::setDosMetaOffset(uint64_t dosmetaoffset)
{
  this->dosmetaoffset = dosmetaoffset;
}

void		FatNode::setCluster(uint32_t cluster)
{
  this->cluster = cluster;
}

void		FatNode::fileMapping(FileMapping* fm)
{
  std::vector<uint64_t>	clusters;
  int			i;
  uint64_t		voffset;
  uint64_t		clustsize;

  clusters = this->fs->fat->clusterChainOffsets(this->cluster);
  voffset = 0;
  clustsize = this->fs->bs->csize * this->fs->bs->ssize;
  for (i = 0; i != clusters.size(); i++)
    {
      fm->push(voffset, clustsize, this->fs->parent, clusters[i]);
      voffset += clustsize;
    }
}



Attributes	FatNode::_attributes()
{
  Attributes	attr; 
  std::vector<uint32_t>	clusters;
  std::list<Variant*>	clustlist;
  int			i;

  //attr->push("dos name", new Variant())
  attr["lfn entries start offset"] =  new Variant(this->lfnmetaoffset);
  attr["dos entry offset"] = new Variant(this->dosmetaoffset);

  uint16_t	mtime;
  uint16_t	mdate;
  uint8_t	mbuff[4];
  vtime* mt = new vtime;
  this->fs->vfile->seek(this->dosmetaoffset+22);
  this->fs->vfile->read(mbuff, 4);
  memcpy(&mtime, mbuff, 2);
  memcpy(&mdate, mbuff+2, 2);
  this->dosToVtime(mt, mtime, mdate);
  attr["modified"] = new Variant(mt);

  uint16_t	adate;
  vtime* at = new vtime;
  this->fs->vfile->seek(this->dosmetaoffset+18);
  this->fs->vfile->read(&adate, 2);
  this->dosToVtime(at, 0, adate);
  attr["accessed"] = new Variant(at);

  uint8_t	ctimetenth;
  uint16_t	ctime;
  uint16_t	cdate;
  uint8_t	cbuff[5];

  vtime* ct = new vtime;
  this->fs->vfile->seek(this->dosmetaoffset+13);
  this->fs->vfile->read(cbuff, 5);
//   for (int i = 0; i != 5; i++)
//     {
//       if (cbuff[i] < 0x10)
// 	printf("0x0%x", cbuff[i]);
//       else
// 	printf("0x%x", cbuff[i]);
//     }
  ctimetenth = *cbuff;
  memcpy(&ctime, cbuff+1, 2);
  memcpy(&cdate, cbuff+3, 2);
  this->dosToVtime(ct, ctime, cdate);
  attr["changed"] = new Variant(ct);

  try
    {
      clusters = this->fs->fat->clusterChain(this->cluster);
      for (i = 0; i != clusters.size(); i++)
	clustlist.push_back(new Variant(clusters[i]));
      attr["allocated clusters"] = new Variant(clustlist);
    }
  catch(vfsError e)
    {
	return attr;
    }
  return attr;
}
