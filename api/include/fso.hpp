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

#ifndef __FSO_HPP__
#define __FSO_HPP__

#ifndef WIN32
  #include <stdint.h>
#else
  #include "wstdint.h"
#endif

#include <string.h>
#include <iostream>
#include <stdio.h>
#include <list>
#include <map>
#include <vector>

#include "variant.hpp"
#include "vfs.hpp"
#include "node.hpp"

typedef std::map<std::string, Variant* > RunTimeArguments; 

class fso
{
private:
  std::list<class Node *>	__update_queue;
public:
  std::map<std::string, Variant* > res;
  std::string			stateinfo;
  std::string			name;

  EXPORT fso(std::string name);
  EXPORT virtual ~fso();
  EXPORT virtual void		start(std::map<std::string, Variant*> args) = 0;
  EXPORT virtual int32_t 	vopen(class Node *n) = 0;
  EXPORT virtual int32_t 	vread(int32_t fd, void *rbuff, uint32_t size) = 0;
  EXPORT virtual int32_t 	vwrite(int32_t fd, void *wbuff, uint32_t size) = 0;
  EXPORT virtual int32_t 	vclose(int32_t fd) = 0;
  EXPORT virtual uint64_t	vseek(int32_t fd, uint64_t offset, int32_t whence) = 0;
  EXPORT virtual uint32_t	status(void) = 0;
  EXPORT virtual uint64_t	vtell(int32_t fd) = 0;
  EXPORT virtual void		setVerbose(bool verbose){}
  EXPORT virtual bool		verbose() { return false; }
  EXPORT std::list<Node *>	updateQueue();
  EXPORT void			registerTree(Node* parent, Node* head);
};

#endif
