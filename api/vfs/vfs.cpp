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
 *  Solal J. <sja@digital-forensic.org>
 */

#include "vfs.hpp"

VFS::VFS()
{
  root = new Node("/");
  //root->name = "";
  //root->path = "";
  //root->is_root = 1; 
  //root->is_file = 0;
  //root->attr = new attrib();
  //root->parent = root;
  //root->fsobj = 0;
  cwd = root;
  //Tree.insert(root);
}

VFS::~VFS()
{
  //DeleteNode(root);
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
  list<Node *>			next;
  list<Node *>::iterator i;

  if (path == "..")
    return (where->parent());
  if (where->hasChildren())
    {
      next = where->children();
      for (i = next.begin(); i != next.end(); i++)
	{
	  if ((*i)->name() == path)
	    return (*i); 
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


// Node* VFS::GetNode(string path, Node* where)
// {
//   list<Node *>next;
//   list<Node *>::iterator i;
  
//   std::cout << path << " " << where->getName() << std::endl;
//   if (path == "..")
//     return (where->getParent());
//   if (where->hasChildren())
//     {
//       for (i = next.begin(); i != next.end(); i++)
// 	{
// 	  if ((*i)->getName() == path)
// 	    return (*i); 
// 	}
//     }
//   else
//     return where;
// }

// Node* VFS::GetNode(string path)
// {
//   uint32_t	pos1;
//   uint32_t	pos2;
//   uint32_t	iter = 0;

//   if (path == "/")
//     return root;
//   while (((pos1 = path.find("/..")) != std::string::npos) && (iter != 10))
//     {
//       if (pos1 == 0)
// 	{
// 	  std::cout << path << " " << pos1 << " " << pos2 << std::endl;
// 	  return NULL;
// 	}
//       pos2 = path.rfind("/", pos1 - 1);
//       std::cout << path << " " << pos1 << " " << pos2 << std::endl;
//       if ((pos2 != std::string::npos) && (pos2 != 1))
// 	path = path.erase(pos2, pos1+3-pos2);
//       iter++;
//     }
//   std::cout << path << std::endl;
//   path = path.substr(path.find('/') + 1);
//   string lpath;
//   string rpath = path;
//   Node* tmp = root;
  
// //   do
// //   {
// //     if (rpath.find('/') != -1)	
// //       {
// // 	lpath = rpath.substr(0, rpath.find('/'));
// // 	rpath = rpath.substr(rpath.find('/') + 1); 
// //       }
// //     else
// //       { 
// // 	lpath = rpath;
// // 	rpath = "";	
// //       }
// //     tmp = GetNode(lpath, tmp);
// //   }  while (tmp && rpath.size());
//   return (tmp);
// }


void VFS::addNode(Node *n)
{
//   n->parent->addchild(n);
//   Tree.insert(n);
//   list<CallBack* >::iterator cb = cbl.begin();
//   for (; cb != cbl.end(); cb++)
//   {
//       (*cb)->cbfunc((*cb)->cbdata, n);
//   }
}

void	VFS::postProcessCallback(Node* node)
{
  list<CallBack* >::iterator	cb_pp;

  for (cb_pp = this->cbl_pp.begin(); cb_pp != this->cbl_pp.end(); cb_pp++)
    (*cb_pp)->cbfunc((*cb_pp)->cbdata, node);
}

void	VFS::recursivePostProcess(Node *node)
{
  std::list<Node*>		children;
  std::list<Node*>::iterator	node_it;

  children = node->children();
  for (node_it = children.begin(); node_it != children.end(); node_it++)
    {
      if ((*node_it)->hasChildren())
	this->recursivePostProcess(*node_it);
      this->postProcessCallback(*node_it);
    }
}

void	VFS::updateCallback(Node* node)
{
  std::list<CallBack*>::iterator	cb;

  for (cb = this->cbl.begin(); cb != this->cbl.end(); cb++)
    (*cb)->cbfunc((*cb)->cbdata, node);
}

void	VFS::update(Node* head)
{
  if (head->hasChildren())
    this->recursivePostProcess(head);
  else
    this->postProcessCallback(head);
  this->updateCallback(head);
}

unsigned int VFS::AddNodes(list<Node*> nl)
{
//   unsigned int num = 0;
//   list<Node* >::iterator n = nl.begin();

//   if (!nl.size())
//     return 0;
//   for(;n  != nl.end(); n++)
//     {
//       (*n)->parent->addchild((*n));
//       Tree.insert((*n));
//       num++;
//       list<CallBack* >::iterator cb_pp = cbl_pp.begin();
//       for (; cb_pp != cbl_pp.end(); cb_pp++)
// 	{
// 	  (*cb_pp)->cbfunc((*cb_pp)->cbdata, *n);
// 	}
//     }
//   list<CallBack* >::iterator cb = cbl.begin();
//   for (; cb != cbl.end(); cb++)
//     {
//       (*cb)->cbfunc((*cb)->cbdata, (*nl.begin()));
//     }
//   return (num);
}

string  VFS::sanitaze(string name, Node* parent)
{
//    string tmp;
//    string::iterator i = name.begin();

//    for (; i != name.end(); ++i)
//    {
//       if (*i >= ' ' && *i <= '~')
//         tmp += *i;
//       else
//         tmp += '\?';
//    }
//    name = tmp;
//    list<Node *>next = parent->next;
//    list<Node*>::iterator n = next.begin();
//    for (; n != next.end(); ++n)
//    {
//      if (name == (*n)->name)
//      {
//        (*n)->same++;
//        char num[11] = {0}; 
//        sprintf(num, "%d", (*n)->same);
//        name += "." + string(num);
//      }
//    }
//   return (name);
}

Node* VFS::CreateNodeDir(fso* fsobj, Node* parent, string name, attrib *attr, bool refresh)
{
//   Node *vp = new Node;

//   if (parent->name.size() == 0)
//     vp->path = "";
//   else
//     vp->path += parent->path + "/" + parent->name;
//   vp->fsobj = fsobj; 
//   vp->name = name;
//   vp->attr = attr;
//   vp->parent = parent;
//   vp->is_file = 0;
//   vp->attr->size = 0;
//   if (refresh == true)
//     addNode(vp);

//   return (vp);
}

Node* VFS::CreateNodeFile(fso* fsobj,  Node* parent, string name, attrib *attr, bool refresh)
{
//   Node *vp = new Node;

//   if (parent->name.size() == 0)
//     vp->path = "";
//   else
//     vp->path += parent->path + "/" + parent->name;
//   vp->fsobj = fsobj;
//   vp->name = name;
//   vp->attr = attr;
//   vp->parent = parent;
//   vp->is_file = 1;
//   if (refresh == true)
//    addNode(vp);

//   return (vp);
}

void	VFS::SetCallBack(CBFUNC func, void* data, string type)
{
  if (type == "refresh_tree")
    cbl.push_back(new CallBack(func, data));
  else if (type == "post_process")
    cbl_pp.push_back(new CallBack(func, data));
}

