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
  Node*			tmp;
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
		  tmp = new Node(dp->d_name, parent, id);
		  tmp->setFsobj(this);
		  tmp->setDecoder(this->attrib);
		  total++;
		  this->iterdir(upath, tmp);
		}
	      else
		{
		  tmp = new Node(dp->d_name, parent, id);
		  tmp->setFsobj(this);
		  tmp->setDecoder(this->attrib);
		  total++;
		}
	    }
	}
      closedir(dfd);
    }
  //res->add_const("nodes created", total);
}

local::local(): mfso("")
{
  this->attrib = new UMetadata();
  //res = new results("local");
  //this->name = "local";
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
  Node*		root;
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
  this->attrib->setBasePath(this->basePath);
  this->root = new Node(path, NULL, id);
  this->root->setFsobj(this);
  this->root->setDecoder(this->attrib);
  if (((stbuff.st_mode & S_IFMT) == S_IFDIR ))
    this->iterdir(tpath->path, this->root);
  this->parent->addChild(this->root);
  return ;
}

int local::vopen(Node *node)
{
  int n;
  struct stat 	stbuff;
  std::string	file;

  std::cout << "OPEN LOCAL" << std::endl;
  file = this->basePath + "/" + node->getPath() + node->getName();
  std::cout << file << std::endl;
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

dff_ui64 local::vseek(int fd, dff_ui64 offset, int whence)
{
 dff_ui64  n = 0;

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

unsigned int local::status(void)
{
  return (nfd);
}
