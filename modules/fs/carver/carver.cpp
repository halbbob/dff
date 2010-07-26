/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
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

#include "carver.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

// Next gen: process like scalpel
//   for each BUFFER
//     for each (header => footer)
//       find()
// implies to preprocess each shift table
// Test if faster or not

CarvedNode::CarvedNode(std::string name, uint64_t size, Node* parent, mfso* fsobj): Node(name, size, parent, fsobj)
{
}

CarvedNode::~CarvedNode()
{
}

void	CarvedNode::setStart(uint64_t start)
{
  this->__start = start;
}

void	CarvedNode::setOrigin(Node* origin)
{
  this->__origin = origin;
}

void	CarvedNode::fileMapping(class FileMapping* fm)
{
  fm->push(0, this->size(), this->__origin, this->__start);
}

Carver::Carver(): mfso("carver")
{
  //res = new results("empty");
}

Carver::~Carver()
{
  //  delete this->header;
  //delete this->footer;
}

uint64_t	Carver::tell()
{
  return this->ifile->tell();
}

void		Carver::Event(DEvent *e)
{
  this->stop = true;
}

void		Carver::start(argument *arg)
{
  try
    {
      attrib	*attr = new attrib;
      arg->get("ifile", &(this->inode));
      this->ifile = this->inode->open();
      this->root = new Node("carved", 0, NULL, this);
      this->root->setDir();
      this->registerTree(this->inode, this->root);
      //this->header = new Header(this->inode);
      //this->footer = new Footer(this->inode);
    }
  catch(vfsError e)
    {
      throw vfsError("Carver::start() throw\n" +  e.error);
    }
}

int		Carver::Read(char *buffer, unsigned int size)
{
  unsigned int bytes_read;

  try
    {
      return (this->ifile->read(buffer, size));
    }
  catch (vfsError e)
    {
      printf("error --> %llu\n", this->ifile->tell());
      return -1;
    }
}

string		Carver::process(list<description *> *d, uint64_t start, bool aligned)
{
  list<description*>::iterator  it;
  context			*tmp;
  int				i;
  
  this->aligned = aligned;
  if (this->ctx.size())
    for (i = 0; i != this->ctx.size(); i++)
      {
  	free(this->ctx[i]->headerBcs);
  	free(this->ctx[i]->footerBcs);
	this->ctx[i]->headers.clear();
	this->ctx[i]->footers.clear();
	delete this->ctx[i]->descr;
	delete this->ctx[i];
      }
  this->ctx.clear();
  if (d->size() > 0)
    {
      this->stop = false;
      this->maxNeedle = 0;
      for (it = d->begin(); it != d->end(); it++)
	{
	  tmp = new context;
	  tmp->descr = *it;
	  tmp->headerBcs = this->bm->generateBcs((*it)->header);
	  tmp->footerBcs = this->bm->generateBcs((*it)->footer);
	  if (this->maxNeedle < (*it)->header->size)
	    this->maxNeedle = (*it)->header->size;
	  if (this->maxNeedle < (*it)->footer->size)
	    this->maxNeedle = (*it)->footer->size;
	  this->ctx.push_back(tmp);
	}
      this->ifile->seek(start, 0);
      this->mapper();
    }
  return this->Results;
}

void		Carver::mapper()
{
  int		i;
  char		*buffer;
  int		bytes_read;
  int		offset;
  DEvent	*e;
  DEvent	*e1;
  uint64_t	total_headers;
  uint64_t	offpos;

  e = new DEvent;
  e1 = new DEvent;
  buffer = (char*)malloc(sizeof(char) * BUFFSIZE);
  int seek;
  e->type = SEEK;
  e1->type = OTHER;
  total_headers = 0;
  while (((bytes_read = this->Read(buffer, BUFFSIZE)) > 0) && (!this->stop))
    {
      offpos = this->tell();
      for (i = 0; i != this->ctx.size(); i++)
	{
	  offset = this->bm->search((unsigned char*)buffer, bytes_read, this->ctx[i]->descr->header, this->ctx[i]->headerBcs);
	  seek = offset;
	  while (offset != -1)
	    {
	      if (this->aligned)
		{
		  if (((this->tell() - bytes_read + seek) % 512) == 0)
		    total_headers += 1;
		}
	      else
		total_headers += 1;
	      this->ctx[i]->headers.push_back(this->tell() - bytes_read + seek);
	      seek += ctx[i]->descr->header->size;
	      offset = this->bm->search((unsigned char*)(buffer+seek), bytes_read - seek, this->ctx[i]->descr->header, this->ctx[i]->headerBcs);
	      seek += offset;
	    }
	  if (this->ctx[i]->descr->footer->size != 0)
	    {
	      offset = this->bm->search((unsigned char*)buffer, bytes_read, this->ctx[i]->descr->footer, this->ctx[i]->footerBcs);
	      seek = offset;
	      while (offset != -1)
		{
		  this->ctx[i]->footers.push_back(this->tell() - bytes_read + seek);
		  seek += ctx[i]->descr->footer->size;
		  offpos = this->tell();
		  offset = this->bm->search((unsigned char*)(buffer+seek), bytes_read - seek, this->ctx[i]->descr->footer, this->ctx[i]->footerBcs);
		  seek += offset;
		}
	    }
	  e1->seek = total_headers;
	  this->notify(e1);
	}
      //e->arg = (void*)this->tell();
      e->seek = this->tell();
      this->notify(e);
      if (bytes_read == BUFFSIZE)
	this->ifile->seek(this->tell() - this->maxNeedle, 0);
    }
  free(buffer);
  this->createTree();
}

std::string	Carver::generateName(uint64_t start, uint64_t end)
{
  ostringstream os;

  os << start << "-" << end;
  return os.str();
}

void		Carver::createNode(Node *parent, uint64_t start, uint64_t end)
{
  CarvedNode*	cn;
  char		name[128];

  sprintf(name, "0x%llx-0x%llx", start, end);
  //std::cout << this->generateName(start, end) << std::endl;

  cn = new CarvedNode(name, end-start, parent, this);
  cn->setFile();
  cn->setStart(start);
  cn->setOrigin(this->inode);
}

unsigned int		Carver::createWithoutFooter(Node *parent, vector<uint64_t> *headers, unsigned int max)
{
  unsigned int	i;
  unsigned int	hlen;
  unsigned int	total;

  hlen = headers->size();
  total = 0;
  for (i = 0; i != hlen; i++)
    {
      if (this->aligned)
	{
	  if (((*headers)[i] % 512) == 0)
	    this->createNode(parent, (*headers)[i], (*headers)[i] + (uint64_t)max);
	  total += 1;
	}
      else
	{
	  this->createNode(parent, (*headers)[i], (*headers)[i] + (uint64_t)max);
	  total += 1;
	}
    }
  return total;
}

unsigned int		Carver::createWithFooter(Node *parent, vector<uint64_t> *headers, vector<uint64_t> *footers, unsigned int max)
{
  unsigned int	i;
  unsigned int	j;
  unsigned int	flen;
  unsigned int	hlen;
  bool		found;
  unsigned int	total;

  hlen = headers->size();
  flen = footers->size();
  j = 0;
  total = 0;
  for (i = 0; i != hlen; i++)
    {
      found = false;
      while ((j != flen) && (!found))
	{
	  if ((*footers)[j] > (*headers)[i])
	    found = true;
	  else
	    j++;
	}
      if (this->aligned)
	{
	  if (((*headers)[i] % 512) == 0)
	    {
	      if (found)
		this->createNode(parent, (*headers)[i], (*footers)[j]);
	      else
		this->createNode(parent, (*headers)[i], (*headers)[i] + (uint64_t)max);
	      total += 1;
	    }
	}
      else
	{
	  if (found)
	    this->createNode(parent, (*headers)[i], (*footers)[j]);
	  else
	    this->createNode(parent, (*headers)[i], (*headers)[i] + (dff_ui64)max);
	  total += 1;
	}
    }
  return total;
}

int		Carver::createTree()
{
  context	*ctx;
  Node		*parent;
  unsigned int	max;
  unsigned int	clen;
  unsigned int	i;
  unsigned int	total;
  char		tmp[42];

  clen = this->ctx.size();
  this->Results = "";
  for (i = 0; i != clen; i++)
    {
      ctx = this->ctx[i];
      if (ctx->headers.size() > 0)
	{
	  parent = new Node(ctx->descr->type, 0, NULL, this);
	  parent->setDir();
	  if (ctx->descr->window > 0)
	    max = ctx->descr->window;
	  else
	    max = BUFFSIZE;
	  if (ctx->footers.size() > 0)
	    total = this->createWithFooter(parent, &(ctx->headers), &(ctx->footers), max);
	  else
	    total = this->createWithoutFooter(parent, &(ctx->headers), max);
	  memset(tmp, 0, 42);
	  sprintf(tmp, "%d", total);
	  this->Results += string(ctx->descr->type) + ":" + string(tmp) + " header(s) found\n";
	  this->registerTree(this->root, parent);
	}
    }
  return 0;
}
