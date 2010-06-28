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
 *  Solal Jacob <sja@digital-forensic.org>
 */

#include "local.hpp"
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <iostream>
#include <sstream>
#include <errno.h>

void local::iterdir(std::string dir, Node *parent)
{
  struct stat		stbuff; 
  struct dirent*	dp;
  DIR*			dfd;
  ULocalNode*		tmp;
  uint64_t		total;
  string		upath;
  uint64_t		id;
  
  if ((dfd = opendir(dir.c_str())))
    {
      while (dp = readdir(dfd))
	{
	  if (!strcmp(dp->d_name, ".")  || !strcmp(dp->d_name, ".."))
	    continue; 
	  upath = dir + "/" + dp->d_name;
	  if (lstat(upath.c_str(), &stbuff) != -1)
	    {
	      if (((stbuff.st_mode & S_IFMT) == S_IFDIR ))
		{
		  tmp = new ULocalNode(dp->d_name, 0, parent, this, ULocalNode::DIR);
		  tmp->setBasePath(&this->basePath);
		  total++;
		  this->iterdir(upath, tmp);
		}
	      else
		{
		  tmp = new ULocalNode(dp->d_name, stbuff.st_size, parent, this, ULocalNode::FILE);
		  tmp->setBasePath(&this->basePath);
		  total++;
		}
	    }
	}
      closedir(dfd);
    }
  //res->add_const("nodes created", total);
}

local::local(): mfso("local")
{
}

local::~local()
{
}

void local::start(argument* arg)
{
  u_attrib*	attr;
  string 	path;
  Path		*tpath;
  struct stat 	stbuff;
  Node*		parent;
  uint64_t	id;
 
  nfd = 0;
  try 
    {
      arg->get("parent", &(this->parent));
    }
  catch (envError e)
    {
      this->parent = VFS::Get().GetNode("/");
    }
  try 
    { 
      arg->get("path", &tpath);
    }
  catch (envError e)
    {
      //res->add_const("error", "conf " + e.error);
      return ;
    }
  if ((tpath->path.rfind('/') + 1) == tpath->path.length())
    tpath->path.resize(tpath->path.rfind('/'));
  path = tpath->path.substr(tpath->path.rfind("/") + 1);
  this->basePath = tpath->path.substr(0, tpath->path.rfind('/'));
  if (stat(tpath->path.c_str(), &stbuff) == -1)
  {
    //res->add_const("error", "stat: " + std::string(strerror(errno)));    	
    return ;
  }
  if (((stbuff.st_mode & S_IFMT) == S_IFDIR ))
    {
      ULocalNode* __root = new ULocalNode(path, 0, NULL, this, ULocalNode::DIR);
      __root->setBasePath(&this->basePath);
      this->_root = __root;
      this->iterdir(tpath->path, this->_root);
    }
  else
    {
      ULocalNode* __root = new ULocalNode(path, stbuff.st_size, NULL, this, ULocalNode::FILE);
      __root->setBasePath(&this->basePath);
      this->_root = __root;
    }
  this->registerTree(this->parent, this->_root);
  return ;
}

int local::vopen(Node *node)
{
  int n;
  struct stat 	stbuff;
  std::string	file;

  file = this->basePath + "/" + node->path() + node->name();
#if defined(__FreeBSD__)
  if ((n = open(file.c_str(), O_RDONLY)) == -1)
#elif defined(__linux__)
    if ((n = open(file.c_str(), O_RDONLY | O_LARGEFILE)) == -1)
#endif
      throw vfsError("local::open error can't open file");
  if (stat(file.c_str(), &stbuff) == -1)
    throw vfsError("local::open error can't stat");
  if (((stbuff.st_mode & S_IFMT) == S_IFDIR ))
    throw vfsError("local::open error can't open directory");
  nfd++;
  return (n);
}

int	local::vread_error(int fd, void *buff, unsigned int size)
{
  unsigned int	pos;
  int		n;
  int		toread;

  pos = 0;
  while (pos < size)
    {
      if (size - pos < 512)
	toread = size - pos;
      else
	toread = 512;
      if ((n = read(fd, ((char*)buff)+pos, toread)) == -1)
	{
	  memset(((char*)buff)+pos, 0, toread);
	  this->vseek(fd, toread, 1);
	}
      pos += toread;
    }
  return size;
}

int local::vread(int fd, void *buff, unsigned int size)
{
  int n;
  
  n = read(fd, buff, size);
  if (n < 0)
  {
    if (errno == EIO)
      {
	return this->vread_error(fd, buff, size);
      }
    else
      throw vfsError("local::vread error read = -1");
  }
  return n;
}

int local::vclose(int fd)
{
  if (close(fd) == -1)
  {
    throw vfsError("local::close error can't close");
  }
  nfd--;
  return (0);
}

uint64_t local::vseek(int fd, uint64_t offset, int whence)
{
 uint64_t  n = 0;

 if (whence == 0)
   whence = SEEK_SET;
 else if (whence == 1)
   whence = SEEK_CUR;
 else if (whence == 2)
   whence = SEEK_END;
#if defined(__FreeBSD__) || defined(__APPLE__)
 n = lseek(fd, offset, whence);
#elif defined(__linux__)
 n = lseek64(fd, offset, whence);
#endif
 if (n == -1)
   {
     throw vfsError("local::vseek can't seek error " + string(strerror(errno)));
   }
 return (n);
}

uint64_t	local::vtell(int32_t fd)
{
  uint64_t	pos;

  pos = this->vseek(fd, 0, 1);
  return pos;
}

unsigned int local::status(void)
{
  return (nfd);
}
