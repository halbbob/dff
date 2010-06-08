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

// Node::Node(std::string name, class Node *parent, uint64_t offset, Metadata* meta)
// {
//   this->name = name;
//   this->parent = parent;
//   this->offset = offset;
//   this->meta = meta;
//   this->childCount = 0;
//   if (this->parent != NULL)
//     this->parent->addChild(this);
// }

FileMapping::FileMapping()
{
  this->__mappedFileSize = 0;
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
  uint32_t		i;
  uint32_t		vsize;
  bool			found;
  uint64_t		maxoffset;

  if (offset > this->__mappedFileSize)
    throw("provided offset too high");
  i = 0;
  vsize = this->__chuncks.size();
  found = false;
  while ((i < vsize) && !found)
    {
      maxoffset = this->__chuncks[i]->offset + this->__chuncks[i]->size;
      if ((offset >= this->__chuncks[i]->offset) && (offset < maxoffset))
	found = true;
      else
	i++;
    }
  if (found)
    {
      return this->__chuncks[i];
    }
  else
    throw("not found");
}

uint32_t	FileMapping::chunckIdxFromOffset(uint64_t offset)
{
  uint32_t	i;
  uint32_t	vsize;
  bool		found;
  uint64_t	maxoffset;

  if (offset > this->__mappedFileSize)
    throw("provided offset too high");
  i = 0;
  vsize = this->__chuncks.size();
  found = false;
  while ((i < vsize) && !found)
    {
      maxoffset = this->__chuncks[i]->offset + this->__chuncks[i]->size;
      if ((offset >= this->__chuncks[i]->offset) && (offset < maxoffset))
	found = true;
      else
	i++;
    }
  if (found)
    {
      return i;
    }
  else
    throw("not found");
}

//XXX Do some sanity checks:
// origin != NULL
// originoffset < origin.size
// originoffset + size < origin.size
void			FileMapping::push(uint64_t offset, uint64_t size, class Node* origin, uint64_t originoffset)
{
  chunck	*c;
  
  c = new chunck;
  c->offset = offset;
  c->size = size;
  this->__mappedFileSize += size;
  c->origin = origin;
  c->originoffset = originoffset;
  this->__chuncks.push_back(c);
}

uint64_t	FileMapping::mappedFileSize()
{
  return this->__mappedFileSize;
}

Attributes::Attributes()
{
  //this->attrs = new std::map<std::string, class Variant*>;
}

Attributes::~Attributes()
{
  //delete this->attrs;
}

void					Attributes::push(std::string key, class Variant *value)
{
  if (value != NULL)
    this->__attrs[key] = value;
  //if (value != NULL)
  //  this->attrs->insert(pair<std::string, class Variant*>(key, value));
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
  this->__childcount = 0;
  this->__mfsobj = fsobj;
  this->__size = size;
  this->__parent = parent;
  if (this->__parent != NULL)
    this->__parent->addChild(this);
  this->__name = name;
}


FileMapping*   Node::fileMapping()
{
  return NULL;
}

Attributes*    Node::attributes()
{
  return NULL;
}

uint64_t	Node::size()
{
  return this->__size;
}

void		Node::setSize(uint64_t size)
{
  this->__size = size;
}

// vtime*		Node::getTimes()
// {
// }

// vtime*		Node::getModifiedTime()
// {
//   return NULL;
// }

// vtime*		Node::getAccessedTime()
// {
//   return NULL;
// }

// vtime*		Node::getCreatedTime()
// {
//   return NULL;
// }

// vtime*		Node::getDeletedTime()
// {
//   return NULL;
// }

Node::~Node()
{
  if (!this->__children.empty())
    this->__children.clear();
}

std::list<class Node*>	Node::children()
{
  return this->__children;
}


bool		Node::setParent(Node *parent)
{
  bool		ret;

  ret = false;
  if (parent != NULL)
    {
      ret = true;
      this->__parent = parent;
    }
  else
    ;//XXX throw() NodeException;
}

// uint64_t	Node::getOffset()
// {
//   return this->offset;
// }

// bool		Node::setDecoder(Metadata *meta)
// {
//   bool		ret;

//   ret = false;
//   if (meta != NULL)
//     {
//       this->meta = meta;
//       ret = true;
//     }
//   else
//     this->meta = NULL;
//   return ret;
// }

uint32_t	Node::childCount()
{
  return this->__childcount;
}


Node*		Node::parent()
{
  return this->__parent;
}


VFile*		Node::open(void)
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
      throw vfsError("MfsoNode::open(void) throw\n" + e.error);
    }
}

void	Node::setFsobj(mfso *obj)
{
  this->__mfsobj = obj;
}


std::string	Node::absolute()
{
  return this->path() + this->__name;
}

std::string	Node::name()
{
  return this->__name;
}


std::string	Node::path()
{
  std::string path;
  Node	*tmp;

  //Root Node
  if (this->__parent == NULL)
    path = this->__name;
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


bool            Node::hasChildren()
{
  if (this->__childcount > 0)
    return true;
  else
    return false;
}


bool		Node::addChild(class Node *child)
{
  child->setParent(this);
  this->__children.push_back(child);
  this->__childcount++;
}
