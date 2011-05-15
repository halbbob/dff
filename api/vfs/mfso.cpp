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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include "mfso.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <pthread.h>

pthread_mutex_t map_mutex = PTHREAD_MUTEX_INITIALIZER;

mfso::mfso(std::string name): fso(name)
{
  this->__fdmanager = new FdManager();
  this->__verbose = false;
  this->__cacheHits = 0;
  allocCache(20); 
}

mfso::~mfso()
{
}

int32_t	mfso::allocCache(uint32_t cacheSize)
{
  this->__cacheSize = cacheSize;
  this->__cacheSlot = (FileMapping**)malloc(sizeof(FileMapping *) *cacheSize); 
  memset(this->__cacheSlot, 0, sizeof(FileMapping*) * cacheSize);

  return (1);
}

FileMapping*		mfso::mapFile(Node* node)
{
  FileMapping*	fm;
  uint32_t	i;

  for (i = 0; i < this->__cacheSize; i++)
  {
     if (this->__cacheSlot[i] != NULL)
     {
       if (node == this->__cacheSlot[i]->node())
       {
	  this->__cacheSlot[i]->setCacheHits(this->__cacheHits++);
	  return (this->__cacheSlot[i]);
       }
     }
  }
 
  for (i = 0; i < this->__cacheSize; i++)
  {
     if (this->__cacheSlot[i] == NULL)
     {
	fm = new FileMapping(node);
        node->fileMapping(fm);
	this->__cacheSlot[i] = fm;
	fm->setCacheHits(this->__cacheHits++);
	return (fm);
     }
  }

  uint64_t  oldest = (this->__cacheSlot[0])->cacheHits(); 
  int32_t   oldestIt = 0;
  for (i = 1; i < this->__cacheSize; i++)
  {
     if (this->__cacheSlot[i] != NULL)
     {
       if ((this->__cacheSlot[i])->cacheHits() < oldest)
       {
          oldest = (this->__cacheSlot[i])->cacheHits();
	  oldestIt = i;
       }
     }
  }
  if (this->__cacheSlot[oldestIt] != NULL)
  {
     fm = this->__cacheSlot[oldestIt];
     this->__cacheSlot[oldestIt] = NULL;
     delete fm;
  }
  this->__cacheSlot[oldestIt] = NULL;
  fm = new FileMapping(node);
  node->fileMapping(fm);
  this->__cacheSlot[oldestIt] = fm;
  fm->setCacheHits(this->__cacheHits++);
  return (fm);
}

VFile*		mfso::vfileFromNode(fdinfo* fi, Node* node)
{
  std::map<fdinfo*, map<Node*,  class VFile* > >::iterator	fdit;
  std::map<Node*, VFile* >::iterator				ndit;
  VFile*							vfile = NULL;

  fdit = this->__origins.find(fi);
  if (fdit != this->__origins.end())
  {
     ndit = fdit->second.find(node);
     if (ndit != fdit->second.end())
     {
        return ndit->second;   
     }
     else
     {
        vfile = node->open();
	pthread_mutex_lock(&map_mutex);
 	fdit->second[node] = vfile;
        pthread_mutex_unlock(&map_mutex);
     }
  }
  else 
  {
     map<Node*, VFile*> mnode;
     vfile = node->open();
     pthread_mutex_lock(&map_mutex);
     mnode[node] = vfile; 
     this->__origins[fi] = mnode;
     pthread_mutex_unlock(&map_mutex);
  }

  return (vfile);
}


int32_t 	mfso::vopen(Node *node)
{
  fdinfo*		fi;
  int32_t		fd;

  if (node != NULL)
    {
      try
	{
	  fi = new fdinfo;
	  fi->offset = 0;
	  fi->node = node;
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
  ostringstream os;

  os << "0x" << hex << val;
  return os.str();
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
	  current = this->mapFile(fi->node)->chunckFromOffset(fi->offset);
	  relativeoffset = current->originoffset + (fi->offset - current->offset);
	  if ((size - totalread) < (current->offset + current->size - fi->offset))
	    relativesize = size - totalread;
	  else
	    relativesize = current->offset + current->size - fi->offset;
	  if (current->origin != NULL)
	    {
	      if (this->__verbose == true)
		{
		  std::cout << "[" << this->name << "] reading " << fi->node->absolute() << std::endl
			    << "   " << hexlify(fi->offset) << "-" << hexlify(fi->offset + relativesize)
			    << " mapped @ " << hexlify(relativeoffset) << "-" << hexlify(relativeoffset + relativesize)
			    << " in " << current->origin->absolute() << std::endl;
		}
	      vfile = this->vfileFromNode(fi, current->origin);
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
		  std::cout << "[" << this->name << "] reading " << fi->node->absolute() << std::endl
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
      if ((fi->node != NULL) && (this->mapFile(fi->node) != NULL))
	{
	  if (fi->node->size() <= this->mapFile(fi->node)->mappedFileSize())
	    {
	      if (size <= (fi->node->size() - fi->offset))
		realsize = size;
	      else
		realsize = fi->node->size() - fi->offset;
	    }
	  else
	    {
	      if (size <= (this->mapFile(fi->node)->mappedFileSize() - fi->offset))
		realsize = size;
	      else
		realsize = this->mapFile(fi->node)->mappedFileSize() - fi->offset;
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
  return 0;
}

uint64_t	mfso::vtell(int32_t fd)
{
  fdinfo*	fi;

  try
    {
      fi = this->__fdmanager->get(fd);
      return fi->offset;
    }
  catch(vfsError e)
    {
	    //throw vfsError("mfso::vtell() throw\n" + e.error);
      return (uint64_t)-1;
    }
}

int32_t 	mfso::vwrite(int32_t fd, void *buff, unsigned int size)
{
	return 0;
}

int32_t 	mfso::vclose(int32_t fd)
{
  fdinfo*	fi;
  std::map<fdinfo*, map<Node*,  class VFile* > >::iterator 	fdit;
  std::map<Node*, VFile* >::iterator				ndit;

  try
  {
     fi = this->__fdmanager->get(fd);
     fdit = this->__origins.find(fi);

     if (fdit != this->__origins.end())
     {
        ndit = fdit->second.begin();
 	for (; ndit != fdit->second.end(); ndit++)
	{
	  ndit->second->close();
 	  delete ndit->second;
	}
	pthread_mutex_lock(&map_mutex);
	fdit->second.clear();
	this->__origins.erase(fdit);
	pthread_mutex_unlock(&map_mutex);
     }
     this->__fdmanager->remove(fd);
  }
  catch (vfsError e)
  {
  }

  return 0;
}

uint64_t	mfso::vseek(int32_t fd, uint64_t offset, int32_t whence)
{
  fdinfo*	fi;

  try
    {
      fi = this->__fdmanager->get(fd);
      switch (whence)
	{
	case 0:
	  if (offset > this->mapFile(fi->node)->mappedFileSize())
	    return (uint64_t)-1;
	  else
	    fi->offset = offset;
	  break;
	case 1:
	  if ((fi->offset + offset) > this->mapFile(fi->node)->mappedFileSize())
	    return (uint64_t)-1;
	  else
	    fi->offset += offset;
	  break;
	case 2:
	  fi->offset = this->mapFile(fi->node)->mappedFileSize();
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
