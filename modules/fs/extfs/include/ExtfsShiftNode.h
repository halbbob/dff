/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 *
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
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

#ifndef __EXTFS_SHIFT_NODE_H_
#define __EXTFS_SHIFT_NODE_H_

#include "node.hpp"

class	Extfs;
class	ExtfsShiftNode : public Node
{
public : 
  ExtfsShiftNode(std::string name, uint64_t size, Node * parent, Extfs * mfsobj);
  ~ExtfsShiftNode();
  
  virtual void	fileMapping(FileMapping* fm);

private :
  Extfs	*	__extfs;
};

#endif
