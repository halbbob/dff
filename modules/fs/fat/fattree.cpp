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

#include "fattree.hpp"

FatTree::FatTree()
{
  //this->ectx = new EntryContext();
  //this->converter = new EntryConverter();
  this->depth = 0;
  this->allocatedClusters = new TwoThreeTree();
}

FatTree::~FatTree()
{
  this->vfile->close();
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
	      if ((c->valid) && (c->cluster < this->fs->bs->totalcluster))
		{
		  if (!c->deleted)
		    {
		      node = this->allocNode(c, parent);
		      if (c->dir)
			{
			  this->depth++;
			  this->walk(c->cluster, node);
			  this->depth--;
			}
		      else
			this->updateAllocatedClusters(c->cluster);
		      delete c;
		    }
		  else
		    this->updateDeletedItems(c, parent);
		}
	      else
		delete c;
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
    {
      node->setDeleted();
      if (this->allocatedClusters->find(c->cluster) == NULL)
	node->setCluster(c->cluster);
      else
	node->setCluster(c->cluster, true);
    }
  else
    node->setCluster(c->cluster);
  node->setLfnMetaOffset(c->lfnmetaoffset);
  node->setDosMetaOffset(c->dosmetaoffset);

  return node;
}

void	FatTree::updateAllocatedClusters(uint32_t cluster)
{
  std::vector<uint32_t>		clusters;
  uint32_t			cidx;

  if (cluster != 0)
    {
      this->allocatedClusters->insert(cluster);
      clusters = this->fs->fat->clusterChain(cluster);
      for (cidx = 0; cidx != clusters.size(); cidx++)
	if (clusters[cidx] != 0)
	  this->allocatedClusters->insert(clusters[cidx]);
    }
}

void	FatTree::updateDeletedItems(ctx* c, Node* parent)
{
  deletedItems*	d;

  d = new deletedItems;
  d->c = c;
  d->node = parent;
  this->deleted.push_back(d);
}

void	FatTree::walk(uint32_t cluster, Node* parent)
{
  std::vector<uint64_t>		clusters;
  uint32_t			cidx;
  uint32_t			bpos;
  uint8_t*			buff;
  Node*				node;
  ctx*				c;

  buff = NULL;
  try
    {
      this->updateAllocatedClusters(cluster);
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
		  if ((c->valid) && (c->cluster < this->fs->bs->totalcluster))
		    {
		      if (!c->deleted)
			{
			  node = this->allocNode(c, parent);
			  if (c->dir)
			    {
			      this->depth++;
			      this->walk(c->cluster, node);
			      this->depth--;
			    }
			  else
			    this->updateAllocatedClusters(c->cluster);
			  delete c;
			}
		      else
			this->updateDeletedItems(c, parent);
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

void	FatTree::walk_free(Node* parent)
{
  std::vector<uint32_t>		clusters;
  uint32_t			cidx;
  uint32_t			bpos;
  uint8_t*			buff;
  Node*				rootunalloc;
  ctx*				c;

  buff = NULL;
  try
    {
      rootunalloc = NULL;
      clusters = this->fs->fat->listFreeClusters();
      buff = (uint8_t*)malloc(this->fs->bs->csize * this->fs->bs->ssize);
      for (cidx = 0; cidx != clusters.size(); cidx++)
	{
	  if ((this->allocatedClusters->find(clusters[cidx]) == NULL) && (clusters[cidx] != 0))
	    {
	      uint64_t	clustoff;
	      clustoff = this->fs->fat->clusterToOffset(clusters[cidx]);
	      this->vfile->seek(clustoff);
	      this->vfile->read(buff, this->fs->bs->csize * this->fs->bs->ssize);
	      for (bpos = 0; bpos != this->fs->bs->csize * this->fs->bs->ssize; bpos += 32)
		{
		  if (*(buff+bpos) == 0xE5)
		    if (this->emanager->push(buff+bpos, clustoff+bpos))
		      {
			c = this->emanager->fetchCtx();
			if (c->valid)
			  {
			    if (rootunalloc == NULL)
			      {
				rootunalloc = new Node("$OrphanedFiles", 0, NULL, this->fs);
				rootunalloc->setDir();
			      }
			    if ((c->size < this->fs->bs->totalsize) && (c->cluster < this->fs->bs->totalcluster))
			      this->allocNode(c, rootunalloc);
			  }
			delete c;
		      }
		}
	    }
	}
      free(buff);
      if (rootunalloc != NULL)
      	this->fs->registerTree(parent, rootunalloc);
    }
  catch(...)
    {
      if (buff != NULL)
	free(buff);
    }  
}

void	FatTree::walkDeleted(uint32_t cluster, Node* parent)
{
  std::vector<uint32_t>		clusters;
  uint64_t			coffset;
  uint32_t			cidx;
  uint32_t			bpos;
  uint8_t*			buff;
  Node*				node;
  ctx*				c;

  buff = NULL;
  if ((this->allocatedClusters->find(cluster) == NULL) && (cluster != 0))
    {
      try
	{
	  clusters = this->fs->fat->clusterChain(cluster);
	  buff = (uint8_t*)malloc(this->fs->bs->csize * this->fs->bs->ssize);
	  for (cidx = 0; cidx != clusters.size(); cidx++)
	    {
	      if ((this->allocatedClusters->find(clusters[cidx]) == NULL) && (clusters[cidx] != 0))
		{
		  coffset = this->fs->fat->clusterToOffset(clusters[cidx]);
		  this->vfile->seek(coffset);
		  this->vfile->read(buff, this->fs->bs->csize * this->fs->bs->ssize);
		  for (bpos = 0; bpos != this->fs->bs->csize * this->fs->bs->ssize; bpos += 32)
		    {
		      if (this->emanager->push(buff+bpos, coffset+bpos))
			{
			  c = this->emanager->fetchCtx();
			  if ((c->valid) && (c->cluster < this->fs->bs->totalcluster))
			    {
			      if (c->deleted)
				{
				  node = this->allocNode(c, parent);
				  this->updateAllocatedClusters(cluster);
				  if ((c->dir) && (this->allocatedClusters->find(c->cluster) == NULL))
				    this->walkDeleted(c->cluster, node);
				  this->updateAllocatedClusters(c->cluster);
				}
			    }
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
}

void	FatTree::processDeleted()
{
  uint32_t	i;
  Node*		node;
  deletedItems*	d;

  for (i = 0; i != this->deleted.size(); i++)
    {
      d = this->deleted[i];
      node = this->allocNode(d->c, d->node);
      if (d->c->dir)
	this->walkDeleted(d->c->cluster, node);
      delete d->c;
      delete d;
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
      this->processDeleted();
      this->fs->registerTree(origin, parent);
      if (this->fs->carveunalloc)
	this->walk_free(parent);
    }
  catch(...)
    {
      throw("err");
    }
}
