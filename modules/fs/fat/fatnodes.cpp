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

#include "fatnodes.hpp"

FatNode::FatNode(std::string name, uint64_t size, Node* parent, class Fatfs* fs): Node(name, size, parent, fs)
{
  this->fs = fs;
}

FatNode::~FatNode()
{
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

void            FatNode::extendedAttributes(Attributes* attr)
{
  std::vector<uint32_t>	clusters;
  std::list<Variant*>	clustlist;
  int			i;

  //attr->push("dos name", new Variant())
  attr->push("lfn entries start offset", new Variant(this->lfnmetaoffset));
  attr->push("dos entry offset", new Variant(this->dosmetaoffset));
  try
    {
      clusters = this->fs->fat->clusterChain(this->cluster);
      for (i = 0; i != clusters.size(); i++)
	clustlist.push_back(new Variant(clusters[i]));
      attr->push("allocated clusters", new Variant(clustlist));
    }
  catch(vfsError e)
    {
    }
}

void            FatNode::modifiedTime(vtime* mt)
{
}

void            FatNode::accessedTime(vtime* at)
{
}

void            FatNode::createdTime(vtime* ct)
{
}



// FatDir::FatDir(std::string name, uint64_t size, Node* parent, Fatfs* fatfs, uint64_t offset, bool deleted): Node(name, size, parent, fatfs)
// {
// }

// FatDir::~FatDir()
// {
// }

// void                  FatDir::extendedAttributes(Attributes* attr)
// {
// }

// void                  FatDir::modifiedTime(vtime* mt)
// {
// }

// void                  FatDir::accessedTime(vtime* at)
// {
// }

// void                  FatDir::createdTime(vtime* ct)
// {
// }


// FatFile::FatFile(std::string name, uint64_t size, Node* parent, Fatfs* fatfs, uint64_t offset, bool deleted): Node(name, size, parent, fatfs)
// {
// }

// FatFile::~FatFile()
// {
// }

// void                  FatFile::extendedAttributes(Attributes* attr)
// {
// }

// void                  FatFile::modifiedTime(vtime* mt)
// {
// }

// void                  FatFile::accessedTime(vtime* at)
// {
// }

// void                  FatFile::createdTime(vtime* ct)
// {
// }

// SlackFile::SlackFile(std::string name, uint64_t size, Node* parent, Fatfs* fatfs, uint64_t offset, bool deleted): Node(name, size, parent, fatfs)
// {
// }

// SlackFile::~SlackFile()
// {
// }
