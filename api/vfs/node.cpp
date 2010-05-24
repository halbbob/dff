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
  this->current = 0;
  this->size = 0;
}

FileMapping::~FileMapping()
{
}

uint64_t		FileMapping::getChunckCount()
{
  return this->chuncks.size();
}

chunck*			FileMapping::getChunck(uint64_t pos)
{
  if (pos < this->chuncks.size())
    return this->chuncks[pos];
  else
    return NULL;
}


chunck*			FileMapping::getFirstChunck()
{
  if (this->chuncks.size() > 0)
    return this->chuncks.front();
  else
    return NULL;
}

chunck*			FileMapping::getLastChunck()
{
  if (this->chuncks.size() > 0)
    return this->chuncks.back();
  else
    return NULL;
}


chunck*			FileMapping::getNextChunck()
{
  chunck*	next;

  if (this->current + 1 < this->chuncks.size())
    {
      next = this->chuncks[this->current + 1];
      this->current += 1;
    }
  else
    return NULL;
}

chunck*			FileMapping::getPrevChunck()
{
  chunck*	prev;

  if ((this->current - 1 < this->chuncks.size()) && (this->current - 1 > 0))
    {
      prev = this->chuncks[this->current - 1];
      this->current -= 1;
    }
  else
    return NULL;
}

std::vector<chunck *>	FileMapping::getChuncks()
{
  return this->chuncks;
}

chunck*			FileMapping::getChunckFromOffset(uint64_t offset)
{
  uint32_t		i;
  uint32_t		size;
  bool			found;
  uint64_t		maxoffset;

  i = 0;
  size = this->chuncks.size();
  found = false;
  while ((i < size) && !found)
    {
      maxoffset = this->chuncks[i]->offset + this->chuncks[i]->size;
      if ((offset >= this->chuncks[i]->offset) && (offset <= maxoffset))
	found = true;
      else
	i++;
    }
  if (found)
    {
      return this->chuncks[i];
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
  this->size += size;
  c->origin = origin;
  c->originoffset = originoffset;
  this->chuncks.push_back(c);
}

uint64_t	FileMapping::getSize()
{
  return this->size;
}

Attributes::Attributes()
{
  this->attrs = new std::map<std::string, class Variant*>;
}

Attributes::~Attributes()
{
  delete this->attrs;
}

void					Attributes::push(std::string key, class Variant *value)
{
  if (value != NULL)
    this->attrs->insert(pair<std::string, class Variant*>(key, value));
}

std::list<std::string>			Attributes::getKeys()
{
  std::list<std::string>		keys;
  std::map<std::string, class Variant*>::iterator it;

  for (it = this->attrs->begin(); it != this->attrs->end(); it++)
    keys.push_back(it->first);
  return keys;
}

Variant*				Attributes::getValue(std::string key)
{
  std::map<std::string, class Variant*>::iterator it;

  it = this->attrs->find(key);
  if (it != this->attrs->end())
    return (it->second);
  else
    return NULL;
}

std::map<std::string, class Variant*>*	Attributes::get()
{
  return this->attrs;
}


Node::Node(std::string name, uint64_t size, Node* parent, mfso* fsobj)
{
  this->childCount = 0;
  this->mfsobj = fsobj;
  this->size = size;
  this->parent = parent;
  if (this->parent != NULL)
    this->parent->addChild(this);
  this->name = name;
}


FileMapping*   Node::getFileMapping()
{
  return NULL;
}

Attributes*    Node::getAttributes()
{
  return NULL;
}

uint64_t	Node::getSize()
{
  return this->size;
}

void		Node::setSize(uint64_t size)
{
  this->size = size;
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
  if (!this->children.empty())
    this->children.clear();
}

std::list<class Node*>	Node::getChildren()
{
  return this->children;
}


bool		Node::setParent(Node *parent)
{
  bool		ret;

  ret = false;
  if (parent != NULL)
    {
      ret = true;
      this->parent = parent;
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

uint32_t	Node::getChildCount()
{
  return this->childCount;
}


Node*		Node::getParent()
{
  return this->parent;
}


VFile*		Node::open(void)
{
  int32_t	fd;
  VFile		*temp;

  if (this->mfsobj == NULL)
    throw vfsError("Can't Open file");
  try
    {
      if ((fd = this->mfsobj->vopen(this)) >= 0)
	{
	  temp = new VFile(fd, this->mfsobj, this);
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
  this->mfsobj = obj;
}


std::string	Node::getName()
{
  return this->name;
}


std::string	Node::getPath()
{
  std::string path;
  Node	*tmp;
  
  tmp = this->parent;
  while (tmp != NULL)
    {
      path = tmp->getName() + "/" + path;
      tmp = tmp->parent;
    }
  return path;
}


bool            Node::hasChildren()
{
  if (this->childCount > 0)
    return true;
  else
    return false;
}


bool		Node::addChild(class Node *child)
{
  this->children.push_back(child);
  this->childCount++;
}
