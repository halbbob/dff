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

#ifndef DUMMY_NODE_H_
#define DUMMY_NODE_H_

#include "dummy.hpp"
#include "node.hpp"

class	DummyNode : public Node
{
 public:
  DummyNode(std::string name, uint64_t size = 0, Node * parent = NULL,
	    Dummy * fsobj = NULL, uint32_t n_entry_addr = 0);
  ~DummyNode();

  virtual void 	fileMapping(FileMapping* fm);
  virtual void	extendedAttributes(Attributes* attr);

  void		modifiedTime(vtime * t);
  void		accessedTime(vtime * t);
  void		createdTime(vtime * t);
  void		changedTime(vtime * t);

private :
  uint32_t	__n_entry_addr;
  Dummy *	__dummy;
};

#endif /* DUMMY_NODE  */
