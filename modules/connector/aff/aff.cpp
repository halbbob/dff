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

pthread_mutex_t io_mutex = PTHREAD_MUTEX_INITIALIZER;


aff::aff() : fso("aff")
{
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
  AFFILE*					 affile;
  AffNode*					 node;

  if (args["parent"])
    this->parent = args["parent"]->value<Node* >();
  else
    this->parent = VFS::Get().GetNode("/");
  if (args["path"])
    vl = args["path"]->value<std::list<Variant* > >();
  else
    throw(envError("aff module requires path argument"));

  for (vpath = vl.begin(); vpath != vl.end(); vpath++)
  {
     std::string path = (*vpath)->value<Path* >()->path;
     affile = af_open(path.c_str(), O_RDONLY, 0);	
     if (affile)
     {
	std::string nname = path.substr(path.rfind('/') + 1);
	node = new AffNode(nname, af_get_imagesize(affile), NULL, this, path);
	af_close(affile);
	this->res[path] = new Variant(std::string("added successfully by aff module"));
     }
     else 
        this->res[path] = new Variant(std::string("can't be added by aff module"));
  }
  this->registerTree(this->parent, node);   

  return ;

}

int aff::vopen(Node *node)
{
  AffNode* affnode = dynamic_cast<AffNode* >(node);
  AFFILE*  affile;

  pthread_mutex_lock(&io_mutex);
  affile = af_open(affnode->originalPath.c_str(), O_RDONLY, 0);
  pthread_mutex_unlock(&io_mutex);
  if (affile)
  {
    fdinfo* fi = new fdinfo();
    fi->id = new Variant((void*)affile);
    return (this->__fdm->push(fi));
  }
  else
    return (-1);
}

int aff::vread(int fd, void *buff, unsigned int size)
{
  int	 	result;
  fdinfo* 	fi = this->__fdm->get(fd);  
  AFFILE*  	affile = (AFFILE*)fi->id->value<void* >();

  pthread_mutex_lock(&io_mutex);
  result = af_read(affile, (unsigned char*)buff, size);
  pthread_mutex_unlock(&io_mutex);

  return (result);
}

int aff::vclose(int fd)
{
  fdinfo* 	fi = this->__fdm->get(fd);
  AFFILE*  	affile = (AFFILE*)fi->id->value<void* >();

  this->__fdm->remove(fd);
  pthread_mutex_lock(&io_mutex);
  af_close(affile);
  pthread_mutex_unlock(&io_mutex);

  return (0);
}

uint64_t aff::vseek(int fd, uint64_t offset, int whence)
{
  uint64_t	result;
  fdinfo* 	fi = this->__fdm->get(fd);
  AFFILE*  	affile = (AFFILE*)fi->id->value<void* >();

  pthread_mutex_lock(&io_mutex);
  result = af_seek(affile, (int64_t)offset, whence);
  pthread_mutex_unlock(&io_mutex);

  return (result);
}

uint64_t	aff::vtell(int32_t fd)
{
  uint64_t  	result;
  fdinfo*	fi = this->__fdm->get(fd);
  AFFILE*  	affile = (AFFILE*)fi->id->value<void* >();

  pthread_mutex_lock(&io_mutex);
  result = af_tell(affile);
  pthread_mutex_unlock(&io_mutex);

  return (result);
}

unsigned int aff::status(void)
{
  return (0);
}
