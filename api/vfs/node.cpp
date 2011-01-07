/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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
  uint32_t	i;

  for (i = 0; i != this->__chuncks.size(); i++)
    delete this->__chuncks[i];
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
	//if (origin != NULL)
	//if (this->__prevChunck != NULL)
	//if ((origin == this->__prevChunck->origin) && (originoffset == (this->__prevChunck->offset + this->__prevChunck->size)))
	//{
	//this->__prevChunck->size += size;
	//this->__mappedFileSize += size;
	//}
	//else
	//this->allocChunck(offset, size, origin, originoffset);
	//else
	//this->allocChunck(offset, size, origin, originoffset);
	//else
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


Node::Node()
{
}

Node::Node(std::string name, uint64_t size, Node* parent, fso* fsobj)
{
  this->__static_attributes = NULL;
  this->__common_attributes = 0;
  this->__childcount = 0;
  this->__at = 0;
  //this->__checkState = 0;
  this->__fsobj = fsobj;
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

void	Node::setFsobj(fso *obj)
{
  this->__fsobj = obj;
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

void   Node::fileMapping(FileMapping *)
{
}

void			Node::setStaticAttribute(std::string key, class Variant* value)
{
  if (this->__static_attributes == NULL)
    this->__static_attributes = new Attributes();
  this->__static_attributes->push(key, value);
}


Attributes*			Node::staticAttributes()
{
  return this->__static_attributes;
}


void			Node::extendedAttributes(Attributes *)
{
}

void			Node::modifiedTime(vtime *)
{
}

void			Node::accessedTime(vtime *)
{
}

void			Node::createdTime(vtime *)
{
}

void			Node::changedTime(vtime *)
{
}

std::map<std::string, vtime*>	Node::times()
{
  std::map<std::string, vtime*>	t;

  //t["modified"] = this->modifiedTime(new vtime);
  vtime *mod = new vtime;
  this->modifiedTime(mod);
  t["modified"] = mod;

  //t["accessed"] = this->accessedTime(new vtime);
  vtime *acc = new vtime;
  this->accessedTime(acc);
  t["accessed"] = acc;

  //t["created"] = this->createdTime(new vtime);
  vtime *crea = new vtime;
  this->createdTime(crea);
  t["created"] = crea;

  //t["changed"] = this->changedTime(new vtime);
  vtime *chan = new vtime;
  this->changedTime(chan);
  t["changed"] = chan;

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

  if (this->__parent == this)
    return "";
  path = "";
  tmp = this->__parent;
  while ((tmp->__parent != tmp) && (tmp->__parent != NULL))
    {
      path = tmp->name() + "/" + path;
      tmp = tmp->parent();
    }
  if (tmp->__parent == tmp)
    path = "/" + path;
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


fso*		Node::fsobj()
{
  return this->__fsobj;
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
  if (0) {
	// FIXME check if child already present
	return false;
  }
  child->setParent(this);
  child->__at = this->__childcount; 
  this->__children.push_back(child);
  this->__childcount++;
  return true;
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


uint32_t	Node::at()
{
  return this->__at;	
}

VFile*		Node::open()
{
  int32_t	fd;
  VFile		*temp;

  if (this->__fsobj == NULL)
    throw vfsError("Can't Open file");
  try
    {
      if ((fd = this->__fsobj->vopen(this)) >= 0)
	{
	  temp = new VFile(fd, this->__fsobj, this);
	  return (temp);
	}
      throw vfsError("Can't Open file");
    }
  catch (vfsError e)
    {
      throw vfsError("Node::open(void) throw\n" + e.error);
    }
}


void	 	Node::setId(uint32_t id)
{
  this->__id = id;
}

uint32_t	Node::id()
{
  return this->__id;
}



VfsRoot::VfsRoot(std::string name): Node(name)
{
  this->setParent(this);
  this->setDir();
}

VfsRoot::~VfsRoot()
{
}

uint32_t VLink::id()
{
  return this->__linkedNode->id();
}


VLink::VLink(Node* linkedNode, Node* parent, std::string newname)
{
  this->__childcount = 0;
  this->__at = 0;
  this->__linkedNode = linkedNode;
  this->__parent = parent;
  
  if (newname == "")
    this->__name = __linkedNode->name(); 
  else
    this->__name = newname;
  this->__parent->addChild(this);
}

void		VLink::fileMapping(FileMapping *fm)
{
  this->__linkedNode->fileMapping(fm);
}

void		VLink::setStaticAttribute(std::string key, class Variant* value)
{
  this->__linkedNode->setStaticAttribute(key, value);
}

Attributes*	VLink::staticAttributes()
{
  return this->__linkedNode->staticAttributes();
}

void		VLink::extendedAttributes(Attributes *attr)
{
  this->__linkedNode->extendedAttributes(attr);
}

void		VLink::modifiedTime(vtime *t)
{
  this->__linkedNode->modifiedTime(t);
}

void		VLink::accessedTime(vtime *t)
{
  this->__linkedNode->accessedTime(t);
}

void 		VLink::createdTime(vtime *t)
{
  this->__linkedNode->createdTime(t);
}

void		VLink::changedTime(vtime *t)
{
  this->__linkedNode->changedTime(t);
}

std::map<std::string, vtime*> VLink::times()
{
  return this->__linkedNode->times();
}

uint64_t	VLink::size()
{
  return this->__linkedNode->size();
}

std::string 	VLink::linkPath()
{
  return this->__linkedNode->path();
}
std::string	VLink::linkName()
{
  return this->__linkedNode->name();
}

std::string 	VLink::linkAbsolute()
{
  return this->__linkedNode->absolute();
}

bool 		VLink::isFile()
{
  return this->__linkedNode->isFile();
}

bool 		VLink::isDir()
{
  return this->__linkedNode->isDir();
}

bool		VLink::isVDir()
{
  return this->__linkedNode->isVDir();
}

bool		VLink::isDeleted()
{
  return this->__linkedNode->isDeleted();
}

bool		VLink::isLink()
{
  return this->__linkedNode->isLink();
}

class fso*	VLink::fsobj()
{
  return this->__linkedNode->fsobj();
}

Node*		VLink::linkParent()
{
  return this->__linkedNode->parent();
}

std::vector<class Node*> VLink::linkChildren()
{
  return this->__linkedNode->children();
}

bool		VLink::linkHasChildren()
{
  return this->__linkedNode->hasChildren();
}

uint32_t	VLink::linkChildCount()
{
  return this->__linkedNode->childCount();
}

Node*		VLink::linkNode()
{
  return this->__linkedNode;
}


VFile*		VLink::open()
{
  return this->__linkedNode->open();
}

VLink::~VLink()
{}

