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

#include "fattree.hpp"

FatTree::FatTree()
{
  //this->ectx = new EntryContext();
  //this->converter = new EntryConverter();
  this->depth = 0;
}

FatTree::~FatTree()
{
}

//void	FatTree::

void	FatTree::rootdir(Node* parent)
{
  uint32_t			bpos;
  uint8_t*			buff;
  Node*				node;
  ctx*				c;

  buff = NULL;
  try
    {
      buff = (uint8_t*)malloc(this->fs->bs->rootdirsize);
      this->vfile->seek(this->fs->bs->rootdiroffset);
      this->vfile->read(buff, this->fs->bs->rootdirsize);
      for (bpos = 0; bpos != this->fs->bs->rootdirsize; bpos += 32)
	{
	  if (this->emanager->push(buff+bpos, this->fs->bs->rootdiroffset + bpos))
	    {
	      c = this->emanager->fetchCtx();
	      //if (c->valid)
	      if (c->valid)
		{
		  node = this->allocNode(c, parent);
		  if ((c->dir) && (!c->deleted) && (c->cluster < this->fs->bs->totalcluster))
		    {
		      this->depth++;
		      //std::cout << "root dir walk on: " << c->dosname << std::endl;
		      this->walk(c->cluster, node);
		      delete c;
		      this->depth--;
		    }
		  else
		    delete c;
		}
	    }
	}
      free(buff);
    }
  catch(...)
    {
      if (buff != NULL)
	free(buff);
    }  
}

void	hexlify(uint8_t *entry)
{
  char		hex[512];
  int		i;
  int		pos;

  memset(hex, 0, 512);
  pos = 0;
  for (i = 0; i != 32; i++)
    {
      if ((i % 4) == 0)
	{
	  sprintf(hex+pos, " ");
	  pos++;
	}
      if ((i == 20) || (i == 21))
	{
	  sprintf(hex+pos, "\e[32m");
	  pos += 5;
	}
      if ((i == 26) || (i == 27))
	{
	  sprintf(hex+pos, "\e[33m");
	  pos += 5;
	}
      if (entry[i] <= 15)
	{
	  sprintf(hex+pos, "0%x ", entry[i]);
	  pos += 3;
	}
      else
	{
	  sprintf(hex+pos, "%x ", entry[i]);
	  pos += 3;
	}
      if ((i == 20) || (i == 21) || (i == 26) || (i == 27))
	{
	  sprintf(hex+pos, "\e[m");
	  pos += 3;
	}
      if (i == 15)
	{
	  sprintf(hex+pos, "\n");
	  pos++;
	}
    }
  printf("%s\n", hex);
}


Node*	FatTree::allocNode(ctx* c, Node* parent)
{
  FatNode*	node;
  
  if (!c->lfnname.empty())
    node = new FatNode(c->lfnname, c->size, parent, this->fs);
  else
    node = new FatNode(c->dosname, c->size, parent, this->fs);
  if (c->dir)
    node->setDir();
  else
    node->setFile();
  if (c->deleted)
    node->setDeleted();
  node->setLfnMetaOffset(c->lfnmetaoffset);
  node->setDosMetaOffset(c->dosmetaoffset);
  node->setCluster(c->cluster);
  return node;
}

bool	FatTree::recurse(uint32_t cluster)
{
  std::list<uint32_t>::iterator	it;

  if (cluster < this->fs->bs->totalcluster)
    return false;
  for (it = this->recursion.begin(); it != this->recursion.end(); it++)
    if (*it == cluster)
      return false;
  return true;
}

void	FatTree::walk(uint32_t cluster, Node* parent)
{
  std::vector<uint64_t>		clusters;
  uint32_t			cidx;
  uint32_t			bpos;
  uint8_t*			buff;
  Node*				node;
  ctx*				c;

  char				space[42];

  buff = NULL;
  try
    {
      clusters = this->fs->fat->clusterChainOffsets(cluster);
      buff = (uint8_t*)malloc(this->fs->bs->csize * this->fs->bs->ssize);
      for (cidx = 0; cidx != clusters.size(); cidx++)
	{
	  this->vfile->seek(clusters[cidx]);
	  this->vfile->read(buff, this->fs->bs->csize * this->fs->bs->ssize);
	  for (bpos = 0; bpos != this->fs->bs->csize * this->fs->bs->ssize; bpos += 32)
	    {
	      if (this->emanager->push(buff+bpos, clusters[cidx]+bpos))
		{
		  c = this->emanager->fetchCtx();
		  if (c->valid)
		    {
		      node = this->allocNode(c, parent);
		      if ((c->dir) && (!c->deleted) && (c->cluster < this->fs->bs->totalcluster))
			{
			  //this->recursion.push_front(c->cluster);
			  this->depth++;
			  this->walk(c->cluster, node);
			  //this->recursion.pop_front();
			  delete c;
			  this->depth--;
			}
		      else
			delete c;
		    }
		}
	    }
	}
      free(buff);
    }
  catch(...)
    {
      if (buff != NULL)
	free(buff);
    }
}

void	FatTree::walk_free(Node* parent)
{
  std::vector<uint64_t>		clusters;
  uint32_t			cidx;
  uint32_t			bpos;
  uint8_t*			buff;
  Node*				rootunalloc;
  ctx*				c;

  buff = NULL;
  try
    {
      rootunalloc = NULL;
      clusters = this->fs->fat->listFreeClustersOffset();
      printf("%d\n", clusters.size());
      buff = (uint8_t*)malloc(this->fs->bs->csize * this->fs->bs->ssize);
      for (cidx = 0; cidx != clusters.size(); cidx++)
	{
	  this->vfile->seek(clusters[cidx]);
	  this->vfile->read(buff, this->fs->bs->csize * this->fs->bs->ssize);
	  for (bpos = 0; bpos != this->fs->bs->csize * this->fs->bs->ssize; bpos += 32)
	    {
	      if (*(buff+bpos) == 0xE5)
		if (this->emanager->push(buff+bpos, clusters[cidx]+bpos))
		{
		  c = this->emanager->fetchCtx();
		  if (c->valid)
		    {
		      if (rootunalloc == NULL)
			{
			  rootunalloc = new Node("unallocated clusters", 0, parent, this->fs);
			  rootunalloc->setDir();
			}
		      //c->dosname = "nothing";
		      if ((c->size < this->fs->bs->totalsize) && (c->cluster < this->fs->bs->totalcluster))
			this->allocNode(c, rootunalloc);
// 		      if (!c->lfnname.empty())
// 			std::cout << c->lfnname << std::endl;
// 		      else
// 			std::cout << c->dosname << std::endl;
		      //node = this->allocNode(c, parent);
		      // 		      if ((c->dir) && (!c->deleted))
// 			{
// 			  this->depth++;
// 			  this->walk(c->cluster, node);
// 			  delete c;
// 			  this->depth--;
// 			}
		    }
		  delete c;
		}
 	    }
	}
      free(buff);
    }
  catch(...)
    {
      if (buff != NULL)
	free(buff);
    }  
}

void	FatTree::process(Node* origin, Fatfs* fs, Node* parent)
{
  this->origin = origin;
  this->fs = fs;
  try
    {
      this->vfile = this->origin->open();
      this->emanager = new EntriesManager(this->fs->bs->fattype);
      if (this->fs->bs->fattype == 32)
	this->walk(this->fs->bs->rootclust, parent);
      else
	this->rootdir(parent);
      this->walk_free(parent);
    }
  catch(...)
    {
      throw("err");
    }
}
