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

#include "ewf.hpp"
#include "ewfnode.hpp"

//mutex_def(io_mutex);

ewf::ewf() : fso("ewf")
{
//  mutex_init(&io_mutex);
  this->__fdm = new FdManager();
}

ewf::~ewf()
{
}

void ewf::start(std::map<std::string, Variant* > args)
{
  std::list<Variant *> vl; 
  std::list<Variant *>::iterator 		 vpath; 
//  EWFNode*					 node;

  if (args["parent"])
    this->parent = args["parent"]->value<Node* >();
  else
    this->parent = VFS::Get().GetNode("/");
  if (args["path"])
    vl = args["path"]->value<std::list<Variant* > >();
  else
    throw(envError("ewf module requires path argument"));
/*
  for (vpath = vl.begin(); vpath != vl.end(); vpath++)
  {
     std::string path = (*vpath)->value<Path* >()->path;
     AFFILE* ewfile = af_open(path.c_str(), O_RDONLY, 0);
     if (ewfile)
     {
	std::string nname = path.substr(path.rfind('/') + 1);
	node = new AffNode(nname, af_get_imagesize(ewfile), NULL, this, path, ewfile);
   	this->registerTree(this->parent, node);   
	this->res[path] = new Variant(std::string("added successfully by ewf module"));
     }
     else 
        this->res[path] = new Variant(std::string("can't be added by ewf module"));
  }
*/
  return ;

}

int ewf::vopen(Node *node)
{
/*  AffNode* ewfNode = dynamic_cast<AffNode* >(node);

  if (ewfNode->ewfile)
  {
    fdinfo* fi = new fdinfo();
    fi->node = node;
    fi->offset = 0;
    return (this->__fdm->push(fi));
  }
  else
    return (-1);*/
}

int ewf::vread(int fd, void *buff, unsigned int size)
{
  int	 	result = -1;
/*
  fdinfo*	fi;
  AffNode*	ewfNode = NULL;

  try
  {
     fi = this->__fdm->get(fd);
     ewfNode = dynamic_cast<AffNode* >(fi->node);
  }
  catch (...)
  {
     return (-1); 
  }

  mutex_lock(&io_mutex);
  af_seek(ewfNode->ewfile, (int64_t)fi->offset, SEEK_SET);
  result = af_read(ewfNode->ewfile, (unsigned char*)buff, size);
  if (result > 0)
    fi->offset += result;
  mutex_unlock(&io_mutex);
*/
  return (result);
}

int ewf::vclose(int fd)
{
  //this->__fdm->remove(fd);

  return (0);
}

uint64_t ewf::vseek(int fd, uint64_t offset, int whence)
{
/*
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
*/
}

uint64_t	ewf::vtell(int32_t fd)
{
/*  
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
*/
}

unsigned int ewf::status(void)
{
  return (0);
}
