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
 *  Solal Jacob <sja@digital-forensic.org>
 */

#include "shm.hpp"

ShmNode::ShmNode(std::string name, uint64_t size, Node* parent, fso* fsobj): Node(name, size, parent, fsobj)
{
  this->setFile();
}

ShmNode::~ShmNode()
{
} 

void	ShmNode::setId(uint32_t id)
{
  this->__id = id;
}

uint32_t	ShmNode::id()
{
  return this->__id;
}


Shm::Shm(): mfso("shm")
{
  this->__fdm = new FdManager();
}

Shm::~Shm()
{
}

void	Shm::start(argument* arg)
{
  Node*		parent;
  string	filename;
  Node*		node;

  try
    {
      arg->get("parent", &parent);
      arg->get("filename", &filename);
      node = this->addnode(parent, filename);
      string n = "file " + node->absolute() + " created\n";
      res->add_const("result", n);
    }
  catch (vfsError e)
    {
      throw vfsError("Vfile::start(argument* arg) throw\n" + e.error);
    }
  return ;
}

Node*	Shm::addnode(Node* parent, string filename)
{
  ShmNode*	node;
  uint32_t	id;
  pdata*	data;
  
  node = new ShmNode(filename, 0, parent, this);
  id = this->__nodesdata.size();
  node->setId(id);
  data = new pdata;
  data->buff = NULL;
  data->len = 0;
  this->__nodesdata.push_back(data);
  return node;
}

int32_t	Shm::vopen(Node *node)
{
  fdinfo*	fi;
  int32_t	fd;

  if (node == NULL)
    throw vfsError("Shm::bad\n"); 
  fi = new fdinfo;
  fi->fm = NULL;
  fi->node = node;
  fi->offset = 0;
  fd = this->__fdm->push(fi);
  return (fd);
}

int32_t		Shm::vread(int32_t fd, void *buff, uint32_t size)
{
  fdinfo*	fi;
  ShmNode*	node;
  uint32_t	id;
  pdata*	data;
  uint32_t	realsize;

  try
    {
      fi = this->__fdm->get(fd);
      node = dynamic_cast<ShmNode*>(fi->node);
      id = node->id();
      if (id > this->__nodesdata.size())
	throw vfsError("Shm: cannot read file");
      data = this->__nodesdata[id];
      if ((node->size() == 0) || (data->len == 0) || (data->len < fi->offset) || (node->size() < fi->offset))
	throw vfsError("Shm: cannot read file");
      if ((data->len - fi->offset) < size)
	size = data->len - fi->offset;
      memcpy(buff, (char *)data->buff + fi->offset, size);
      fi->offset += size;
      return (size);
    }
  catch (const std::exception& e)
    {
      throw vfsError("Shm cannot read file\n");
    }
  catch (vfsError e)
    {
      throw vfsError("Shm cannot read file\n" + e.error);
    }
}

int32_t		Shm::vwrite(int32_t fd, void *buff, uint32_t size) 
{
  fdinfo*	fi;
  ShmNode*	node;
  uint32_t	id;
  pdata*	data;

  try
    {
      fi = this->__fdm->get(fd);
      node = dynamic_cast<ShmNode*>(fi->node);
      id = node->id();
      if (id > this->__nodesdata.size())
	throw vfsError("Shm: cannot write file");
      data = this->__nodesdata[id];
      if (data->len < fi->offset)
	throw vfsError("Shm: cannot write file");
      if (data->len == 0)
	{
	  data->buff = new char[size];
	  data->len = size;
	}
      else if (data->len < (fi->offset + size))
	{
	  size = (uint32_t)(fi->offset + size - data->len);
	  data->buff = realloc(data->buff, sizeof(char) * (data->len + size));
	  data->len += size;
	}
      memcpy((char*)data->buff + fi->offset, buff, size);
      fi->offset += size;
      node->setSize(data->len);
      return size;
    }
  catch (const std::exception& e)
    {
      throw vfsError("Shm cannot write file\n");
    }
  catch (vfsError e)
    {
      throw vfsError("Shm cannot write file\n" + e.error);
    }
}

uint64_t	Shm::vseek(int32_t fd, uint64_t offset, int32_t whence)
{
  fdinfo*	fi;
  ShmNode*	node;
  uint32_t	id;

  try
    {
      fi = this->__fdm->get(fd);
      node = dynamic_cast<ShmNode*>(fi->node);
      id = node->id();
      if (id > this->__nodesdata.size())
	throw vfsError("Shm: cannot seek");
      if (whence == 0)
	if (offset < node->size())
	  fi->offset = offset;
	else
	  throw vfsError("Shm: cannot seek");
      else if (whence == 1)
	if (fi->offset + offset < node->size())
	  fi->offset += offset;
	else
	  throw vfsError("Shm: cannot seek");
      else if (whence == 2)
	fi->offset = node->size();
      return (fi->offset);
    }
  catch (const std::exception& e)
    {
      throw vfsError("Shm: cannot seek\n");
    }
  catch (vfsError e)
    {
      throw vfsError("Shm cannot vseek file\n" + e.error);
    }
}

int32_t		Shm::vclose(int32_t fd)
{
//XXX del fp
  try
    {
      this->__fdm->remove(fd);
      return (0);
    }
  catch (const std::exception& e)
    {
      throw vfsError("Shm: fd already close");
    }
}

uint64_t	Shm::vtell(int32_t fd)
{
  fdinfo*	fi;
  ShmNode*	node;
  uint32_t	id;

  try
    {
      fi = this->__fdm->get(fd);
      return (fi->offset);
    }
  catch (const std::exception& e)
    {
      throw vfsError("Shm: cannot tell");
    }
}

uint32_t	Shm::status(void)
{
  return (0);
}

