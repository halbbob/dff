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
 */

#include "mfso.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

FdManager::FdManager()
{
  this->fds.assign(16384, (fdinfo*)0);
  this->allocated = 0;
}

FdManager::~FdManager()
{
}

fdinfo*		FdManager::get(int32_t fd)
{
  fdinfo*	fi;

  //  std::cout << "getting info from fd " << fd << std::endl;
  if (fd > this->fds.size())
    throw(vfsError("fdmanager::get -> Provided fd is too high"));
  else
    {
      fi = this->fds[fd];
      if (fi != 0)
	{
	  //std::cout << "fd found" << std::endl;
	  return fi;
	}
      else
	throw(vfsError("fdmanager::get -> fd not allocated"));
      //;return NULL;
    }
}

int32_t	FdManager::push(fdinfo* fi)
{
  int32_t	i;
  bool		empty;

  empty = false;
  if (this->allocated == this->fds.size())
    throw(vfsError("fdmanager::push -> there is no room for new fd"));
  else
    {
      i = 0;
      while ((i < this->fds.size()) && !empty)
	{
	  if (this->fds[i] == 0)
	    empty = true;
	  else
	    i++;
	}
      if (empty && i < this->fds.size())
	{
	  this->allocated++;
	  this->fds[i] = fi;
	  return i;
	}
      else
	throw(vfsError("fdmanager::push -> new fd allocation failed"));
    }
}

void		FdManager::remove(int32_t fd)
{
  fdinfo*	fi;
  
  if (fd > this->fds.size())
    {
      std::cout << "fdmanager::remove -> fd not allocated" << std::endl;
      //throw(vfsError("fdmanager::remove -> fd not allocated"));
    }
  else
    {
      fi = this->fds[fd];
      if (fi != 0)
	{
	  delete fi;
	  this->fds[fd] = 0;
	  this->allocated--;
	}
    }
}

fso::fso(std::string name)
{
  this->name = name;
  this->res = new results(this->name);
  this->stateinfo = "";
}

fso::~fso()
{
}

mfso::mfso(std::string name): fso(name)
{
  this->__fdmanager = new FdManager();
  this->__verbose = false;
  //this->root = new Node(NULL, name, 0);
}

mfso::~mfso()
{
}

void	fso::registerTree(Node* parent, Node* head)
{
  parent->addChild(head);
  //this->__parent = parent->fsobj();
  VFS::Get().update(head);
}

// bool		mfso::registerDecoder(std::string name, Decoder&)
// {
// }

// bool		mfso::unregisterDecoder(std::string name)
// {
// }

// Node		*createNode(Node *parent, Decoder *decoder, uint64_t offset)
// {
// }

//std::string		mfso::name()
//{
//return this->__name;
//}


VFile*		mfso::vfileFromNode(Node* n)
{
  std::map<Node*, class VFile*>::iterator	it;
  VFile*					vfile;

  it = this->__origins.find(n);
  if (it != this->__origins.end())
    {
      //std::cout << "already opened" << std::endl;
      return it->second;
    }
  else
    {
      //      std::cout << "Not yet opened" << std::endl;
      vfile = n->open();
      this->__origins[n] = vfile;
      return vfile;
    }
    
}


int32_t 	mfso::vopen(Node *node)
{
  FileMapping		*fm;
  fdinfo*		fi;
  int32_t		fd;

  if (node != NULL)
    {
      try
	{
	  //Check if mapping of the node is already in the cache
	  fi = new fdinfo;
          fm = new FileMapping; //delete when ? 
	  node->fileMapping(fm);
	  fi->offset = 0;
	  fi->node = node;
	  fi->fm = fm;
	  fd = this->__fdmanager->push(fi);
	  return fd;
	}
      catch(...)
	{
	  return -1;
	}
    }
  else
    throw("Node null");
  return -1;
}

std::string	hexlify(uint64_t val)
{
  char		res[32];
  
  snprintf(res, 32, "0x%llx", val);
  return res;
}

void			mfso::setVerbose(bool verbose)
{
  this->__verbose = verbose;
}

bool			mfso::verbose()
{
  return this->__verbose;
}

int32_t		mfso::readFromMapping(fdinfo* fi, void* buff, uint32_t size)
{
  VFile*	vfile;
  chunck*	current;
  uint64_t	relativeoffset;
  uint32_t	currentread;
  uint32_t	totalread;
  bool		eof;
  uint32_t	relativesize;

  eof = false;
  totalread = 0;
  while ((totalread != size) && (!eof))
    {
      try
	{
	  current = fi->fm->chunckFromOffset(fi->offset);
	  relativeoffset = current->originoffset + (fi->offset - current->offset);
	  if ((size - totalread) < (current->offset + current->size - fi->offset))
	    relativesize = size - totalread;
	  else
	    relativesize = current->offset + current->size - fi->offset;
	  if (current->origin != NULL)
	    {
	      if (this->__verbose == true)
		{
		  std::cout << "[" << this->__name << "] reading " << fi->node->absolute() << std::endl
			    << "   " << hexlify(fi->offset) << "-" << hexlify(fi->offset + relativesize)
			    << " mapped @ " << hexlify(relativeoffset) << "-" << hexlify(relativeoffset + relativesize)
			    << " in " << current->origin->absolute() << std::endl;
		}
	      vfile = this->vfileFromNode(current->origin);
	      vfile->seek(relativeoffset);
	      if ((currentread = vfile->read(((uint8_t*)buff)+totalread, relativesize)) == 0)
		eof = true;
	      fi->offset += currentread;
	      totalread += currentread;
	    }
	  else if (current->size != 0)
	    {
	      memset((uint8_t*)buff+totalread, 0, relativesize);
	      if (this->__verbose == true)
		{
		  std::cout << "[" << this->__name << "] reading " << fi->node->absolute() << std::endl
			    << "   " << hexlify(fi->offset) << "-" << hexlify(fi->offset + relativesize)
			    << " mapped @ " << hexlify(relativeoffset) << "-" << hexlify(relativeoffset + relativesize)
			    << " in shadow node" << std::endl;
		}
	      fi->offset += relativesize;
	      totalread += relativesize;
	    }
	  else
	    throw("chunck is not valid");
	}
      catch(...)
	{
	  eof = true;
	}
    }
  return totalread;
}


int32_t 	mfso::vread(int32_t fd, void *buff, uint32_t size)
{
  fdinfo*	fi;
  uint64_t	realsize;
  int32_t	bytesread;

  try
    {
      fi = this->__fdmanager->get(fd);
      if ((fi->node != NULL) && (fi->fm != NULL))
	{
	  if (fi->node->size() <= fi->fm->mappedFileSize())
	    {
	      if (size <= (fi->node->size() - fi->offset))
		realsize = size;
	      else
		realsize = fi->node->size() - fi->offset;
	    }
	  else
	    {
	      if (size <= (fi->fm->mappedFileSize() - fi->offset))
		realsize = size;
	      else
		realsize = fi->fm->mappedFileSize() - fi->offset;
	    }
	  bytesread = this->readFromMapping(fi, buff, realsize);
	  return bytesread;
	}
      else
	return 0;
    }
  catch(...)
    {
      //throw(vfsError("problem while reading file"));
    }
}

uint64_t	mfso::vtell(int32_t fd)
{
  fdinfo*	fi;

  try
    {
      fi = this->__fdmanager->get(fd);
      return fi->offset;
    }
  catch(...)
    {
      std::cout << "problem while getting fd information" << std::endl;
      return (uint64_t)-1;
    }
}

//need COW implementation to reflect forensically sound process
int32_t 	mfso::vwrite(int32_t fd, void *buff, unsigned int size)
{
	return 0;
}

int32_t 	mfso::vclose(int32_t fd)
{
  try
    {
      this->__fdmanager->remove(fd);
    }
  catch (vfsError e)
    {
    }
  return 0;
}

//need same implementation of lseek syscall ?
uint64_t	mfso::vseek(int32_t fd, uint64_t offset, int32_t whence)
{
  fdinfo*	fi;

  try
    {
      fi = this->__fdmanager->get(fd);
      switch (whence)
	{
	case 0:
	  if (offset > fi->fm->mappedFileSize())
	    return (uint64_t)-1;
	  else
	    fi->offset = offset;
	  break;
	case 1:
	  if ((fi->offset + offset) > fi->fm->mappedFileSize())
	    return (uint64_t)-1;
	  else
	    fi->offset += offset;
	  break;
	case 2:
	  fi->offset = fi->fm->mappedFileSize();
	  break;
	}
      return fi->offset;
    }
  catch(...)
    {
      std::cout << "problem while getting fd information" << std::endl;
      return (uint64_t)-1;
    }
}

uint32_t	mfso::status(void)
{
  return 0;
}
