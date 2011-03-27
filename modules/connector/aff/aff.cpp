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

aff::aff() : fso("aff")
{
  this->__fdm = new FdManager();
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
	node = new AffNode(name, af_get_imagesize(affile), NULL, this, path);
	af_close(affile);
	this->res[path] = new Variant(std::string("added successfully by aff module"));
     }
     else 
        this->res[path] = new Variant(std::string("can't be added by aff module"));
  }
  this->registerTree(this->parent, node);   

//  this->res[""]
  return ;

}

int aff::vopen(Node *node)
{
  AffNode* affnode = dynamic_cast<AffNode* >(node);
  AFFILE*  affile;

  affile = af_open(affnode->originalPath.c_str(), O_RDONLY, 0);
  if (affile)
  {
    fdinfo* fi = new fdinfo();
    fi->id = new Variant((void*)affile);
    int fd = this->__fdm->push(fi);
    return fd;
  }
  else
    return (0);
}

int aff::vread(int fd, void *buff, unsigned int size)
{
  fdinfo* fi = this->__fdm->get(fd);
  AFFILE*  affile = (AFFILE*)fi->id->value<void* >();
  return (af_read(affile, (unsigned char*)buff, size));
}

int aff::vclose(int fd)
{
  fdinfo* fi = this->__fdm->get(fd);
  AFFILE*  affile = (AFFILE*)fi->id->value<void* >();
  return (af_close(affile));
}

uint64_t aff::vseek(int fd, uint64_t offset, int whence)
{
  fdinfo* fi = this->__fdm->get(fd);
  AFFILE*  affile = (AFFILE*)fi->id->value<void* >();
  return (af_seek(affile, offset, whence));
}

uint64_t	aff::vtell(int32_t fd)
{
  fdinfo* fi = this->__fdm->get(fd);
  AFFILE*  affile = (AFFILE*)fi->id->value<void* >();
  return (af_tell(affile));
}

unsigned int aff::status(void)
{
  return (0);
}
