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
}

FileMapping::~FileMapping()
{
}

chunck*			FileMapping::getNextChunck()
{
}

chunck*			FileMapping::getPrevChunck()
{
}

std::vector<chunck *>	FileMapping::getChuncks()
{
}

void			FileMapping::push(class Node* from, uint64_t start, uint64_t end)
{
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


Node::Node(std::string name, Node* parent, mfso* fsobj)
{
  this->mfsobj = fsobj;
  this->parent = parent;
  if (this->parent != NULL)
    this->parent->addChild(this);
  this->name = name;
}


FileMapping*   Node::getFileMapping()
{
}

Attributes*    Node::getAttributes()
{
  std::cout << "Node getattributes :(" << std::endl;
}


// vtime*		Node::getTimes()
// {
// }

vtime*		Node::getModifiedTime()
{
}

vtime*		Node::getAccessedTime()
{
}

vtime*		Node::getCreatedTime()
{
}

vtime*		Node::getDeletedTime()
{
}

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

