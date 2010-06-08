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
    throw("Provided fd is too high");
  else
    {
      fi = this->fds[fd];
      if (fi != 0)
	{
	  //std::cout << "fd found" << std::endl;
	  return fi;
	}
      else
	throw("Fd not allocated");
      //;return NULL;
    }
}

int32_t	FdManager::push(fdinfo* fi)
{
  int32_t	i;
  bool		empty;

  empty = false;
  if (this->allocated == this->fds.size())
    throw("Fd manager Full");
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
	throw("Allocation failed");
    }
}

void		FdManager::remove(int32_t fd)
{
  fdinfo*	fi;
  
  if (fd > this->fds.size())
    throw("Provided fd is too high");
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

mfso::mfso(std::string name)
{
  this->__name = name;
  this->__res = new results(this->__name);
  this->__fdmanager = new FdManager();
  this->__stateinfo = "";
  //this->root = new Node(NULL, name, 0);
}

mfso::~mfso()
{
}

void	mfso::registerTree(Node* parent, Node* head)
{
  parent->addChild(head);
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

std::string		mfso::name()
{
  return this->__name;
}

results*		mfso::res()
{
  return this->__res;
}

void			mfso::setStateInfo(std::string stateinfo)
{
  this->__stateinfo = stateinfo;
}

std::string		mfso::stateInfo()
{
  return this->__stateinfo;
}

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
	  fm = node->fileMapping();
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
  while ((totalread != size) && !eof)
    {
      //std::cout << "fd offset: " << fi->offset << std::endl;//""
      try
	{
	  current = fi->fm->chunckFromOffset(fi->offset);	
	  if (current->origin != NULL)
	    {
	      relativeoffset = current->originoffset + (fi->offset - current->offset);
	      vfile = this->vfileFromNode(current->origin);
	      vfile->seek(relativeoffset);
	      relativesize = current->offset + current->size - fi->offset;
	      if ((size - totalread) < relativesize)
		relativesize = size - totalread;
	      currentread = vfile->read(((uint8_t*)buff)+totalread, relativesize);
	      std::cout << "offset " << fi->offset << " of " << fi->node->path() << fi->node->name() 
			<< " is at offset " << relativeoffset << " in node "
			<< current->origin->path() + current->origin->name() << std::endl;
	      fi->offset += currentread;
	      totalread += currentread;
	    }
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
	  //Warn if fi->node->getSize() != fm->getSize() ?
	  if (size > (fi->fm->mappedFileSize() - fi->offset))
	    realsize = fi->fm->mappedFileSize() - fi->offset;
	  else
	    realsize = size;
	  bytesread = this->readFromMapping(fi, buff, realsize);
	  return bytesread;
	}
      else
	return 0;
    }
  catch(...)
    {
      std::cout << "problem while reading node" << std::endl;
      return 0;
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
}

int32_t 	mfso::vclose(int32_t fd)
{
  this->__fdmanager->remove(fd);
}

//need same implementation of lseek syscall ?
uint64_t	mfso::vseek(int32_t fd, uint64_t offset, int whence)
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
	case 1:
	  if ((fi->offset + offset) > fi->fm->mappedFileSize())
	    return (uint64_t)-1;
	  else
	    fi->offset += offset;
	case 2:
	  fi->offset = fi->fm->mappedFileSize();
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
