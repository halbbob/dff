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

#ifndef EXTFS_NODE_H_
#define EXTFS_NODE_H_

#include "data_structure/includes/extfs_struct/ext4/extents.h"
#include "node.hpp"

class Extfs;
class Inode;

class	ExtfsNode : public Node
{
 public:
  ExtfsNode(std::string name, uint64_t size = 0, Node * parent = NULL,
	    Extfs * fsobj = NULL, uint64_t inode_addr = 0, bool is_root = false);
  ~ExtfsNode();

  //! return NULL if an error occurs.
  virtual void 	fileMapping(FileMapping* fm);

  //! return NULL if an error occurs.
  virtual void	extendedAttributes(Attributes* attr);

  void		modifiedTime(vtime * t);
  void		accessedTime(vtime * t);
  void		createdTime(vtime * t);
  void		changedTime(vtime * t);

  void		push_block_pointers(Inode * inode, FileMapping * file_mapping);
  void		set_i_nb(uint64_t i_id);
  uint64_t	i_nb() const;

 private :
  Inode *	read_inode();

  uint64_t	__inode_addr;
  uint64_t	__i_nb;
  Extfs *	__extfs;
  bool		__is_root;
};

#endif /* EXTFS_NODE_H_ */