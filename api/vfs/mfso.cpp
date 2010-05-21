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
  this->vector.assign(16384, 0);
}

FdManager::~FdManager()
{
}

fdinfo*		FdManager::get(uint32_t fd)
{
  fdinfo*	fi;

  if (fd > this->fds.size())
    throw("Provided fd is too high");
  else
    {
      fi = this->fds[fd];
      if (fi != 0)
    }
}

uint32_t	FdManager::push(fdinfo* fi)
{
  uint32_t	i;
  bool		empty;

  empty = false;
  if (this->allocated == this->fds.size())
    throw("Fd manager Full");
  else
    {
      i = 0;
      while ((i != this->fds.size()) && !empty)
	{
	  if (this->fds[i] != 0)
	    empty = true;
	  else
	    i++;
	}
      this->allocated++;
      return i;
    }
}

void		FdManager::remove(uint32_t fd)
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

  if (node != NULL)
    {
      fm = node->getFileMapping();
      if (fm != NULL)
	{
	  fi = new fdinfo;
	  fi->offset = 0;
	  fi->fm = fm;
	  try
	    {
	      fd = this->fdmanager->push(fi);
	      return fd;
	    }
	  catch(...)
	    {
	      return -1;
	    }
	}
      else
	;
    }
  else
    throw("Node null");
  return -1;
}

int32_t 	mfso::vread(int fd, void *buff, unsigned int size)
{
}

int32_t 	mfso::vwrite(int fd, void *buff, unsigned int size)
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
