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
 *  Solal Jacob <sja@digital-forensic.org>
 */

#include "aff.hpp"
#include "affnode.hpp"
#include <pthread.h>

mutex_def(io_mutex);

aff::aff() : fso("aff")
{
  mutex_init(&io_mutex);
  this->__affile = NULL;
  this->__fdm = new FdManager();
  setenv("AFFLIB_CACHE_PAGES", "2", 1);
}

aff::~aff()
{
}

void aff::start(std::map<std::string, Variant* > args)
{
  std::list<Variant *> vl; 
  std::list<Variant *>::iterator 		 vpath; 
  AffNode*					 node;

  if (args["parent"])
    this->parent = args["parent"]->value<Node* >();
  else
    this->parent = VFS::Get().GetNode("/");
  if (args["path"])
    vl = args["path"]->value<std::list<Variant* > >();
  else
    throw(envError("aff module requires path argument"));
//if args['cahe_size'] //set cache size 

//XXX can't open multiple different file !
  for (vpath = vl.begin(); vpath != vl.end(); vpath++)
  {
     std::string path = (*vpath)->value<Path* >()->path;
     this->__affile = af_open(path.c_str(), O_RDONLY, 0);	
     if (this->__affile)
     {
	std::string nname = path.substr(path.rfind('/') + 1);
	node = new AffNode(nname, af_get_imagesize(this->__affile), NULL, this, path);
   	this->registerTree(this->parent, node);   
	this->res[path] = new Variant(std::string("added successfully by aff module"));
     }
     else 
        this->res[path] = new Variant(std::string("can't be added by aff module"));
  }

  return ;

}

int aff::vopen(Node *node)
{
  if (this->__affile)
  {
    fdinfo* fi = new fdinfo();
    fi->node = node;
    fi->offset = 0;
    return (this->__fdm->push(fi));
  }
  else
    return (-1);
}

int aff::vread(int fd, void *buff, unsigned int size)
{
  int	 	result;
  fdinfo*	fi;
 
  try
  {
     fi = this->__fdm->get(fd);
  }
  catch (...)
  {
     return (-1); 
  }

  mutex_lock(&io_mutex);
  af_seek(this->__affile, (int64_t)fi->offset, SEEK_SET);
  result = af_read(this->__affile, (unsigned char*)buff, size);
  if (result > 0)
    fi->offset += result;
  mutex_unlock(&io_mutex);

  return (result);
}

int aff::vclose(int fd)
{
  this->__fdm->remove(fd);

  return (0);
}

uint64_t aff::vseek(int fd, uint64_t offset, int whence)
{
  Node*	node;
  fdinfo* fi;

  try
  {
     fi = this->__fdm->get(fd);
     node = fi->node;

     if (whence == 0)
     {
        if (offset <= node->size())
        {
           fi->offset = offset;
           return (fi->offset);
        } 
     }
     else if (whence == 1)
     {
        if (fi->offset + offset <= node->size())
        {
           fi->offset += offset;
	   return (fi->offset);
        }
     }
     else if (whence == 2)
     {
        fi->offset = node->size();
        return (fi->offset);
     }
  }
  catch (...)
  {
     return ((uint64_t) -1);
  }

  return ((uint64_t) -1);
}

uint64_t	aff::vtell(int32_t fd)
{
  fdinfo*	fi;

  try
  {
     fi = this->__fdm->get(fd);
     return (fi->offset);
  }
  catch (...)
  {
     return (uint64_t)-1; 
  }
}

unsigned int aff::status(void)
{
  return (0);
}
