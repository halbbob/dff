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
 *  Solal J. <sja@digital-forensic.org>
 */

#include "vfs.hpp"

VFS&	VFS::Get()
{ 
    static VFS single;
    return single;
}

VFS::VFS()
{
  this->root = new VfsRoot("/");
  this->__orphanednodes.push_back(this->root);
  cwd = root;
}

VFS::~VFS()
{
}

void	VFS::Event(event *e)
{
}

void VFS::cd(Node *path)
{
  cwd = path;
}

Node* VFS::GetCWD(void)
{
  return (cwd);
}

set<Node *>* VFS::GetTree(void)
{
  return (&Tree);
}

uint16_t	VFS::registerFsobj(fso* fsobj) throw (vfsError)
{
  if (fsobj != NULL)
    this->__fsobjs.push_back(fsobj);
  else
    throw (vfsError("registerFsobj() NULL pointer provided"));
  return (uint16_t)(this->__fsobjs.size());
}

uint64_t	VFS::registerOrphanedNode(Node* n) throw (vfsError)
{
  if (n != NULL)
    this->__orphanednodes.push_back(n);
  else
    throw (vfsError("registerOrphanedNode() NULL pointer provided"));
  return (uint64_t)(this->__orphanednodes.size() - 1);
}

std::vector<fso*>	VFS::fsobjs()
{
  return this->__fsobjs;
}

uint64_t	VFS::totalNodes()
{
  int	i;
  uint64_t	totalnodes;

  totalnodes = this->__orphanednodes.size();
  for (i = 0; i != this->__fsobjs.size(); i++)
    totalnodes += this->__fsobjs[i]->nodeCount();
  return totalnodes;
}

Node*	VFS::getNodeById(uint64_t id)
{
  uint16_t	fsoid;
  fso*		fsobj;

  fsoid = id >> 48;
  if ((fsoid == 0) && (id < this->__orphanednodes.size()))
    return this->__orphanednodes[id];
  else if ((fsoid > 0) && ((fsoid - 1) < this->__fsobjs.size()))
    {
      if ((fsobj = this->__fsobjs[fsoid-1]) != NULL)
	return fsobj->getNodeById(id);
      else
	return NULL;
    }
  else
    return NULL;
}

Node* VFS::GetNode(string path, Node* where)
{
  std::vector<Node *>	next;
  uint32_t		i;

  if (path == "..")
    return (where->parent());
  if (where->hasChildren())
    {
      next = where->children();
      for (i = 0; i < next.size(); i++)
	{
	  if (next[i]->name() == path)
	    return (next[i]); 
	}
      return (0);
    }
  else
    return (0);
}



Node* VFS::GetNode(string path)
{
  if (path == "/")
    return root;	
  path = path.substr(path.find('/') + 1);
  string lpath;
  string rpath = path;
  Node* tmp = root;
  do
  {
    if (rpath.find('/') != std::string::npos)
      {
	lpath = rpath.substr(0, rpath.find('/'));
	rpath = rpath.substr(rpath.find('/') + 1); 
      }
    else
      { 
	lpath = rpath;
	rpath = "";
      }
    tmp = GetNode(lpath, tmp);
  }  while (tmp && rpath.size());
  return (tmp);
}

void	VFS::AddNode(Node *parent, Node* head)
{
   parent->addChild(head);
   event* e = new event;
   e->value = new Variant(head);
   this->notify(e);
}
