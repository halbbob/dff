/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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

#include "fdmanager.hpp"

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

  if (fd > this->fds.size())
    throw(vfsError("fdmanager::get -> Provided fd is too high"));
  else
    {
      fi = this->fds[fd];
      if (fi != 0)
	return fi;
      else
	throw(vfsError("fdmanager::get -> fd not allocated"));
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
