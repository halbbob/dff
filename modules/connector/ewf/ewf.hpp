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
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __EWF_HH__
#define __EWF_HH__


#include "fso.hpp"
#include "node.hpp"
#include <string>
#include <iostream>
#include <stdio.h>
#include <list>
#include <vector>
#include "variant.hpp"
#include "vfs.hpp"
#include "path.hpp"
#include "fdmanager.hpp"
#include "threading.hpp"
#include <fcntl.h>
//#include <afflib/afflib.h>
//#include <afflib/afflib_i.h>


class ewf : public fso
{
private:
  Node		*parent;
  FdManager*	__fdm;
public:
  ewf();
  ~ewf();
  int32_t		vopen(Node* handle);
  int32_t 		vread(int fd, void *buff, unsigned int size);
  int32_t 		vclose(int fd);
  uint64_t 		vseek(int fd, uint64_t offset, int whence);
  int32_t		vwrite(int fd, void *buff, unsigned int size) { return 0; };
  uint32_t		status(void);
  uint64_t		vtell(int32_t fd);
  virtual void		start(std::map<std::string, Variant* > args);
};
#endif
