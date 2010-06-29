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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "ulocalnode.hpp"

ULocalNode::ULocalNode(std::string Name, uint64_t size, Node* parent, mfso* fsobj, uint8_t type): Node(Name, size, parent, fsobj)
{
  switch (type)
    {
    case DIR:
      this->setDir();
      break;
    case FILE:
      this->setFile();
      break;
    default:
      break;
    }
}

ULocalNode::~ULocalNode()
{
}

vtime*			ULocalNode::modifiedTime()
{
  vtime*	t;
  struct stat*	st;
  
  if ((st = this->localStat()) != NULL)
    {
      t = this->utimeToVtime(&(st->st_mtime));
      return t;
    }
  else
    return NULL;
}

vtime*			ULocalNode::accessedTime()
{
  vtime*	t;
  struct stat*	st;
  
  if ((st = this->localStat()) != NULL)
    {
      t = this->utimeToVtime(&(st->st_atime));
      return t;
    }
  else
    return NULL;
}

vtime*			ULocalNode::changedTime()
{
  vtime*	t;
  struct stat*	st;
  
  if ((st = this->localStat()) != NULL)
    {
      t = this->utimeToVtime(&(st->st_ctime));
      return t;
    }
  else
    return NULL;
}

void		ULocalNode::setBasePath(std::string* bp)
{
  this->basePath = bp;
}

vtime*		ULocalNode::utimeToVtime(time_t* tt)
{
  vtime*	vt;
  struct tm*	t;

  if (tt != NULL)
    {
      if ((t = gmtime(tt)) != NULL)
	{
	  vt = new vtime();
	  vt->year = t->tm_year + 1900;
	  vt->month = t->tm_mon + 1;
	  vt->day = t->tm_mday;
	  vt->hour = t->tm_hour;
	  vt->minute = t->tm_min;
	  vt->second = t->tm_sec;
	  vt->dst = t->tm_isdst;
	  vt->wday = t->tm_wday;
	  vt->yday = t->tm_yday;
	  vt->usecond = 0;
	  return vt;
	}
      else
	return NULL;
    }
  else
    return NULL;
}

struct stat*	ULocalNode::localStat()
{
  std::string	file;
  struct stat* 	st;

  file = *(this->basePath) + this->path() + this->name();
  st = (struct stat*)malloc(sizeof(struct stat));
  if (lstat(file.c_str(), st) != -1)
    return st;
  else
    {
      free(st);
      return NULL;
    }
}

Attributes*	ULocalNode::attributes()
{
  Attributes*	attr;
  struct stat*	st;

  if ((st = this->localStat()) != NULL)
    {
      attr = new Attributes();
      attr->push("size", new Variant(st->st_size));
      attr->push("uid", new Variant(st->st_uid));
      attr->push("gid", new Variant(st->st_gid));
      attr->push("inode", new Variant(st->st_ino));
      free(st);
      return attr;
    }
  else
    return NULL;
}
