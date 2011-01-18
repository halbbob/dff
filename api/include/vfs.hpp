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

// \brief This class implements the virtual file system of the framework.

// The Virtual File System (VFS) is a central point of the framework.
// It permits to register nodes and browse them.

#ifndef __VFS_HH__
#define __VFS_HH__

#include "vfile.hpp"
#include "export.hpp"
#include "exceptions.hpp"
#include "node.hpp"
#include "DEventHandler.hpp"
#include "node.hpp"

#include <vector>
#include <deque>
#include <list>
#include <set>

class VFS: public DEventHandler
{  
private:
  EXPORT 	        VFS();
  EXPORT                ~VFS();
  VFS&          operator=(VFS&);
                VFS(const VFS&);

public:
  class Node*           cwd;	
  Node*		        root;
  set<Node*>            Tree;

  static VFS&   Get() 
  { 
    static VFS single; 
    return single; 
  }

  EXPORT virtual void	Event(DEvent *e);
  EXPORT set<Node*>*    GetTree(void);
  EXPORT void 	        cd(Node *);
  EXPORT Node* 	        GetCWD(void);
  EXPORT Node*	        GetNode(string path);
  EXPORT Node*	        GetNode(string path, Node* where);
  EXPORT void		AddNode(Node *parent, Node* head);
};

#endif
