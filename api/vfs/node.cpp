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
 *  Solal J. <sja@digital-forensic.org>
 */

#include "node.hpp"

FileMapping::FileMapping()
{
  this->__mappedFileSize = 0;
  this->__prevChunck = NULL;
}

FileMapping::~FileMapping()
{
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
// 	  std::cout << "begidx: " << begidx << " mididx: " << mididx << " endidx: " << endidx
// 		    << " offset: " << offset << " mididx->offset: " << this->__chuncks[mididx]->offset << std::endl;
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
  if (origin != NULL)
    if (this->__prevChunck != NULL)
      if ((origin == this->__prevChunck->origin) && (originoffset == (this->__prevChunck->offset + this->__prevChunck->size)))
	{
	  this->__prevChunck->size += size;
	  this->__mappedFileSize += size;
	}
      else
	this->allocChunck(offset, size, origin, originoffset);
    else
      this->allocChunck(offset, size, origin, originoffset);
  else
    this->allocChunck(offset, size, origin, originoffset);
}


uint64_t	FileMapping::mappedFileSize()
{
  return this->__mappedFileSize;
}

Attributes::Attributes()
{
}

Attributes::~Attributes()
{
}

void					Attributes::push(std::string key, class Variant *value)
{
  if (value != NULL)
    this->__attrs[key] = value;
}

std::list<std::string>			Attributes::keys()
{
  std::list<std::string>		keys;
  std::map<std::string, class Variant*>::iterator it;

  for (it = this->__attrs.begin(); it != this->__attrs.end(); it++)
    keys.push_back(it->first);
  return keys;
}

Variant*				Attributes::value(std::string key)
{
  std::map<std::string, class Variant*>::iterator it;

  it = this->__attrs.find(key);
  if (it != this->__attrs.end())
    return (it->second);
  else
    return NULL;
}

std::map<std::string, class Variant*>	Attributes::attributes()
{
  return this->__attrs;
}


Node::Node(std::string name, uint64_t size, Node* parent, mfso* fsobj)
{
  this->__common_attributes = 0;
  this->__childcount = 0;
  this->__mfsobj = fsobj;
  this->__size = size;
  this->__parent = parent;
  if (this->__parent != NULL)
    this->__parent->addChild(this);
  this->__name = name;
}

Node::~Node()
{
  if (!this->__children.empty())
    this->__children.clear();
}

void		Node::setFile()
{
  if (!this->isDir())
    this->__common_attributes |= ISFILE;
  else
    throw("attribute ISDIR already setted");
}

void		Node::setDir()
{
  if (!this->isFile())
    this->__common_attributes |= ISDIR;
  else
    throw("attribute ISFILE already setted");
}

void		Node::setLink()
{
  this->__common_attributes |= ISLINK;
}

void		Node::setDeleted()
{
  this->__common_attributes |= ISDELETED;
}

void		Node::setSize(uint64_t size)
{
  this->__size = size;
}

void	Node::setFsobj(mfso *obj)
{
  this->__mfsobj = obj;
}

void		Node::setParent(Node *parent)
{
  if (parent != NULL)
    {
      this->__parent = parent;
      //this->__parent->addChild(this);
    }
  else
    ;//XXX throw() NodeException;
}


FileMapping*   Node::fileMapping()
{
  return NULL;
}

Attributes*    Node::attributes()
{
  return NULL;
}

vtime*			Node::modifiedTime()
{
  return NULL;
}

vtime*			Node::accessedTime()
{
  return NULL;
}

vtime*			Node::createdTime()
{
  return NULL;
}

vtime*			Node::changedTime()
{
  return NULL;
}

std::map<std::string, vtime*>	Node::times()
{
  std::map<std::string, vtime*>	t;

  t["modified"] = this->modifiedTime();
  t["accessed"] = this->accessedTime();
  t["created"] = this->createdTime();
  t["changed"] = this->changedTime();
  return t;
}

uint64_t	Node::size()
{
  return this->__size;
}

std::string	Node::path()
{
  std::string path;
  Node	*tmp;

  //Root Node
  if (this->__parent == NULL)
    path = "";
  else
    {
      tmp = this->__parent;
      path = "";
      while (tmp->parent() != NULL)
	{
	  path = tmp->name() + "/" + path;
	  tmp = tmp->parent();
	}
      path = "/" + path;
    }
  return path;
}

std::string	Node::name()
{
  return this->__name;
}

std::string	Node::absolute()
{
  return this->path() + this->__name;
}

bool				Node::isFile()
{
  if ((this->__common_attributes & ISFILE) == ISFILE)
    return true;
  else
    return false;
}

bool				Node::isDir()
{
  if ((this->__common_attributes & ISDIR) == ISDIR)
    return true;
  else
    return false;
}

bool				Node::isLink()
{
  if ((this->__common_attributes & ISLINK) == ISLINK)
    return true;
  else
    return false;
}

bool				Node::isVDir()
{
  if (this->isFile() && this->hasChildren())
    return true;
  else
    return false;
}

bool				Node::isDeleted()
{
  if ((this->__common_attributes & ISDELETED) == ISDELETED)
    return true;
  else
    return false;
}


mfso*		Node::fsobj()
{
  return this->__mfsobj;
}

Node*		Node::parent()
{
  return this->__parent;
}

std::vector<class Node*>	Node::children()
{
  return this->__children;
}

bool		Node::addChild(class Node *child)
{
  child->setParent(this);
  this->__children.push_back(child);
  this->__childcount++;
}

bool            Node::hasChildren()
{
  if (this->__childcount > 0)
    return true;
  else
    return false;
}

uint32_t	Node::childCount()
{
  return this->__childcount;
}

VFile*		Node::open()
{
  int32_t	fd;
  VFile		*temp;

  if (this->__mfsobj == NULL)
    throw vfsError("Can't Open file");
  try
    {
      if ((fd = this->__mfsobj->vopen(this)) >= 0)
	{
	  temp = new VFile(fd, this->__mfsobj, this);
	  return (temp);
	}
      throw vfsError("Can't Open file");
    }
  catch (vfsError e)
    {
      throw vfsError("Node::open(void) throw\n" + e.error);
    }
}
