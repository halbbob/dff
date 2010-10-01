/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
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

#include "extfs.hpp"
#include "include/ExtfsShiftNode.h"

ExtfsShiftNode::ExtfsShiftNode(std::string name, uint64_t size, Node * parent,
			       Extfs * mfsobj)
  : Node  (name, size, parent, mfsobj)
{
  __extfs = mfsobj;
}

ExtfsShiftNode::~ExtfsShiftNode()
{
}

void	ExtfsShiftNode::fileMapping(FileMapping* fm)
{
  uint64_t	fs_size, offset;

  fs_size = __extfs->SB()->block_size() * __extfs->SB()->blocks_number();
  offset = __extfs->SB()->offset() - __BOOT_CODE_SIZE;
  //  fm->push(0, fs_size, __extfs->node1(), offset);
}

void	ExtfsShiftNode::extendedAttributes(Attributes* attr)
{
}
