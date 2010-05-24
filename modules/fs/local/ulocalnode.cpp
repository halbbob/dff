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
#include "utype.hpp"

ULocalNode::ULocalNode(std::string Name, Node* parent, mfso* fsobj): Node(Name, parent, fsobj)
{
}

ULocalNode::~ULocalNode()
{
}

void		ULocalNode::setBasePath(std::string* bp)
{
  this->basePath = bp;
}

Attributes*	ULocalNode::getAttributes()
{
  Attributes*	attr;
  std::string	file;
  struct stat 	st;

  file = *(this->basePath) + "/" + this->getPath() + this->name;
  if (lstat(file.c_str(), &st) != -1)
    {
      attr = new Attributes();
      attr->push("size", new Variant(st.st_size));
      attr->push("uid", new Variant(st.st_uid));
      attr->push("gid", new Variant(st.st_gid));
      attr->push("inode", new Variant(st.st_ino));
      attr->push("accessed", new Variant(new u_vtime(gmtime(&st.st_atime))));
      attr->push("modified", new Variant(new u_vtime(gmtime(&st.st_mtime))));
      attr->push("changed", new Variant(new u_vtime(gmtime(&st.st_ctime))));
      return attr;
    }
  else
    return NULL;
}
