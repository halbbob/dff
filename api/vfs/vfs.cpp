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
 *  Solal J. <sja@digital-forensic.org>
 */

#include "vfs.hpp"

VFS::VFS()
{
  root = new VfsRoot("/");
  cwd = root;
}

VFS::~VFS()
{
}

void	VFS::Event(event *e)
{
}

void VFS::cd(Node *path)
{
  cwd = path;
}

Node* VFS::GetCWD(void)
{
  return (cwd);
}

set<Node *>* VFS::GetTree(void)
{
  return (&Tree);
}

Node* VFS::GetNode(string path, Node* where)
{
  std::vector<Node *>	next;
  uint32_t		i;

  if (path == "..")
    return (where->parent());
  if (where->hasChildren())
    {
      next = where->children();
      for (i = 0; i < next.size(); i++)
	{
	  if (next[i]->name() == path)
	    return (next[i]); 
	}
      return (0);
    }
  else
    return (0);
}



Node* VFS::GetNode(string path)
{
  if (path == "/")
    return root;	
  path = path.substr(path.find('/') + 1);
  string lpath;
  string rpath = path;
  Node* tmp = root;
  do
  {
     if (rpath.find('/') != -1)	
     {
       lpath = rpath.substr(0, rpath.find('/'));
       rpath = rpath.substr(rpath.find('/') + 1); 
     }
     else
     { 
       lpath = rpath;
       rpath = "";
     }
     tmp = GetNode(lpath, tmp);
  }  while (tmp && rpath.size());
  return (tmp);
}


void	VFS::AddNode(Node *parent, Node* head) /* peut m ettre un s du coup mouahhaha
ou alors chopper une lsite ce qui evite les for ....... koi ct comme ca avant ????
*/
{
   parent->addChild(head);
 
   DEvent* e = new DEvent(head);
   this->notify(e);
}
