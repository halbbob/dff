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

#ifndef __DUMMY_H_
# define __DUMMY_H_
 
#include "type.hpp"
#include "vfs.hpp"
#include "argument.hpp"
#include "mfso.hpp"

typedef struct entry_s
{
  uint16_t	offset;
  uint8_t	name[8];
  uint16_t	size;
  uint32_t	fragment;
}		entry_t;
 
class   Dummy : public mfso
{
public:
  Dummy();                                 
  ~Dummy();
 
  /*
     The paramters "arg" of type arguments * contains the list of arguments which were past
     to the module (graphically or in command line). When the module is used, the "start"
     method is called.
  */
  virtual void          start(argument *arg);

  VFile *		vfile;
  class DummyNode *	root_node;
  Node *		node;
};
 
#endif /* __DUMMY_H_ */
