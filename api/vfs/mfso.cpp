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

  std::cout << "getting info from fd " << fd << std::endl;
  if (fd > this->fds.size())
    throw("Provided fd is too high");
  else
    {
      fi = this->fds[fd];
      if (fi != 0)
	{
	  std::cout << "fd found" << std::endl;
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
  this->name = name;
  this->res = new results(name);
  this->fdmanager = new FdManager();
  //this->root = new Node(NULL, name, 0);
}

mfso::~mfso()
{
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


int32_t 	mfso::vopen(Node *node)
{
  FileMapping	*fm;
  fdinfo*	fi;
  int32_t	fd;

  if (node != NULL)
    {
      try
	{
	  //Check if mapping of the node is already in the cache
	  fm = fi->node->getFileMapping();
	  fi = new fdinfo;
	  fi->offset = 0;
	  fi->node = node;
	  fi->fm = fm;
	  fd = this->fdmanager->push(fi);
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

  try
    {
      eof = false;
      totalread = 0;
      current = fi->fm->getChunckFromOffset(fi->offset);
      while ((totalread != size) && !EOF)
	{
	  if ((current->offset + current->size) < fi->offset)
	    current = fi->fm->getChunckFromOffset(fi->offset);
	  if (current->origin != NULL)
	    {
	      relativeoffset = fi->offset - current->offset;
	      vfile = current->origin->open();
	      vfile->seek(relativeoffset);
	      currentread += vfile->read(((uint8_t*)buff)+totalread, size - totalread);
	      fi->offset += currentread;
	      totalread += currentread;
	      std::cout << "offset " << fi->offset << " of " << fi->node->getPath() << fi->node->getName() 
			<< " is at offset " << current->originoffset + relativeoffset << " in node " 
			<< current->origin->getPath() + current->origin->getName() << std::endl;
	    }
	  else
	    eof = true;
	}
    }
  catch(...)
    {
      std::cout << "error with FileMapping" << std::endl;
      return -1;
    }
}

int32_t 	mfso::vread(int32_t fd, void *buff, uint32_t size)
{
  fdinfo*	fi;
  uint64_t	realsize;
  int32_t	bytesread;

  try
    {
      fi = this->fdmanager->get(fd);
      if ((fi->node != NULL) && (fi->fm != NULL))
	{
	  //Warn if fi->node->getSize() != fm->getSize() ?
	  if (size > (fi->fm->getSize() - fi->offset))
	    realsize = fi->fm->getSize() - fi->offset;
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

int32_t 	mfso::vwrite(int32_t fd, void *buff, unsigned int size)
{
}

int32_t 	mfso::vclose(int32_t fd)
{
  this->fdmanager->remove(fd);
}

uint64_t	mfso::vseek(int32_t fd, uint64_t offset, int whence)
{
}

uint32_t	mfso::status(void)
{
  return 0;
}
