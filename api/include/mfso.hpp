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

#ifndef __MFSO_HPP__
#define __MFSO_HPP__

#ifndef WIN32
  #include <stdint.h>
#else
  #include "wstdint.h"
#endif

#include <iostream>
#include <stdio.h>
#include <list>
#include <map>
#include <vector>
#include <string.h>

#include "fso.hpp"
#include "fdmanager.hpp"
#include "vfile.hpp"

class mfso: public fso
{
private:
  std::map<fdinfo *, map <Node*, class VFile*> >			__origins;
  class VFile*					__vfile;
  std::list<class mfso*>			__children;
  class mfso					*__parent;

  bool						__verbose;

  class VFile*					vfileFromNode(fdinfo* fi, Node* n);
  int32_t					readFromMapping(fdinfo* fi, void* buff, uint32_t size);

public:
  FdManager*					__fdmanager;
  EXPORT mfso(std::string name);
  EXPORT virtual ~mfso();
  EXPORT virtual void		start(std::map<std::string, Variant*> args) = 0;
  EXPORT virtual int32_t 	vopen(class Node *n);
  EXPORT virtual int32_t 	vread(int32_t fd, void *buff, uint32_t size);
  EXPORT virtual int32_t 	vwrite(int32_t fd, void *buff, uint32_t size);
  EXPORT virtual int32_t 	vclose(int32_t fd);
  EXPORT virtual uint64_t	vseek(int32_t fd, uint64_t offset, int32_t whence);
  EXPORT virtual uint32_t	status(void);
  EXPORT virtual uint64_t	vtell(int32_t fd);


  EXPORT virtual void		setVerbose(bool verbose);
  EXPORT virtual bool		verbose();
};

#endif
