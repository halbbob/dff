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

mfso::mfso(std::string name): fso(name)
{
  this->__fdmanager = new FdManager();
  this->__verbose = false;
}

mfso::~mfso()
{
}

VFile*		mfso::vfileFromNode(fdinfo* fi, Node* node)
{//vfilefromnodeandfi ! attention delete le cache de fi quand y a un close !
  std::map<fdinfo*, map<Node*,  class VFile* > >::iterator	fdit;
  std::map<Node*, VFile* >::iterator						ndit;
  VFile*	vfile = NULL;

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
	  fdit->second[node] = vfile;
	}

  }
  else 
  {
    map<Node*, VFile*> mnode = this->__origins[fi];
	vfile = node->open();
	mnode[node] = vfile; 
	this->__origins[fi] = mnode;
  }
  return (vfile);
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
	  fi = new fdinfo;
          fm = new FileMapping;
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
  std::map<fdinfo*, map<Node*,  class VFile* > >::iterator fdit;
  std::map<Node*, VFile* >::iterator						ndit;

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
		 fdit->second.clear();
		 this->__origins.erase(fdit);
	  }

      delete fi->fm;
	  delete fi;
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
