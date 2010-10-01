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

//#define FM_DEBUG

#include "include/ExtfsNode.h"
#include "data_structure/includes/Inode.h"
#include "data_structure/includes/Ext4Extents.h"
#include "include/MfsoAttrib.h"
#include "include/CustomResults.h"

ExtfsNode::ExtfsNode(std::string name, uint64_t size, Node* parent,
		     Extfs * fsobj, uint64_t inode_addr, bool is_root)
  : Node (name, size, parent, fsobj)
{
  this->__inode_addr = inode_addr;
  this->__extfs = fsobj;
  this->__i_nb = 0;
  this->__is_root = is_root;
}

ExtfsNode::~ExtfsNode()
{
}

void	ExtfsNode::fileMapping(FileMapping* fm)
{
  Inode * inode = read_inode();

  if (!inode)
    return ;
  if (inode->flags() & 0x80000) // Use extent. (should be defined in Inode.h)
    {
      Ext4Extents * ext4 = new Ext4Extents(fm);
      ext4->push_extended_blocks(inode);
      delete ext4;
    }
  else
    push_block_pointers(inode, fm);

#ifdef FM_DEBUG
  std::cout << "------------ displaying chunks ----------" << std::endl;
  std::vector<chunck *>	v = fm->chuncks();
  std::vector<chunck *>::iterator it = v.begin();
  while (it != v.end())
    {
      std::cout << "originoffset : " << (*it)->originoffset << std::endl;
      std::cout << "size : " << (*it)->size << std::endl;
      std::cout << "offset : " << (*it)->offset << std::endl << std::endl;
      it++;
    }
  std::cout << "------------ Done ----------------------" << std::endl;
#endif

  delete inode->inode();
  delete inode;
}

void		ExtfsNode::push_block_pointers(Inode * inode,
					       FileMapping * file_mapping)
{
  uint64_t	blk_addr, offset = 0, size;
  uint64_t	b_size = __extfs->SB()->block_size();
  uint64_t      ooffset = __extfs->SB()->offset() - __BOOT_CODE_SIZE;
  uint32_t	tmp = inode->SB()->block_size() / sizeof(uint32_t);

  size = this->size();
  if (!size)
    return ;
  while ((inode->currentBlock() < ((tmp * tmp * tmp) + (tmp * tmp) + 12)))
    {
      blk_addr = inode->nextBlock();
      if (!blk_addr)
	{
	  if (inode->currentBlock() < 12)
	    continue ;
	  if (inode->currentBlock() < tmp + 12)
	    {
	      if (!(inode->simple_indirect_block_pointer()))
		inode->goToBlock(tmp + 12);
	    }
	  else if (inode->currentBlock() < ((tmp * tmp) + 12))
	    {
	      if (!inode->double_indirect_block_pointer())
		inode->goToBlock((tmp * tmp) + 12);
	    }
	  else if (!inode->triple_indirect_block_pointer())
	    {
	      if (offset < size)
		this->setSize(offset);
	      break ;
	    }
	}
      else if (__extfs->SB()->block_size() < size)
	{
	  size -= b_size;
	  file_mapping->push(offset, b_size, __extfs->node(),
			     blk_addr * __extfs->SB()->block_size() + ooffset);
	  offset += inode->SB()->block_size();
	}
      else
	{
	  file_mapping->push(offset, size, __extfs->node(),
			     blk_addr * __extfs->SB()->block_size() + ooffset);
	  break ;
	}
    }
}

void	ExtfsNode::extendedAttributes(Attributes* attr)
{
  Inode	*	inode = read_inode();

  if (!inode)
    return ;
  if (__is_root)
    {
      CustomResults c_res;
      c_res.set(attr, inode);
    }
  else
    {
      MfsoAttrib * c_attr = new MfsoAttrib;
      c_attr->setAttrs(inode, attr, __i_nb, __inode_addr);
      delete c_attr;
    }
  delete inode->inode();
  delete inode;
}

void		ExtfsNode::modifiedTime(vtime * t)
{
  Inode	*	inode = read_inode();

  if (!inode)
    return ;

  delete t;
  MfsoAttrib * c_attr = new MfsoAttrib;
  t = c_attr->vtime_from_timestamp(inode->modif_time());

  delete inode->inode();
  delete inode;
}

void		ExtfsNode::accessedTime(vtime * t)
{
  Inode	*	inode = read_inode();

  if (!inode)
    return ;

  delete t;
  MfsoAttrib * c_attr = new MfsoAttrib;
  t = c_attr->vtime_from_timestamp(inode->access_time());

  delete inode->inode();
  delete inode;
}

void		ExtfsNode::createdTime(vtime * t)
{
  Inode * inode = read_inode();
  if (!inode)
    return ;
  delete t;
  if (inode->SB()->inodes_struct_size() > sizeof(inodes_t))
    {
      uint8_t * tab = (uint8_t *)operator new(sizeof(__inode_reminder_t));
      __inode_reminder_t * i_reminder = (__inode_reminder_t *)tab;

      inode->extfs()->vfile()->read(tab, sizeof(__inode_reminder_t));
      MfsoAttrib * c_attr = new MfsoAttrib;
      t = c_attr->vtime_from_timestamp(i_reminder->creation_time);
    }
  delete inode->inode();
  delete inode;
  
}

void		ExtfsNode::changedTime(vtime * t)
{
  Inode	*	inode = read_inode();

  if (!inode)
    return ;

  delete t;
  MfsoAttrib * c_attr = new MfsoAttrib;
  t = c_attr->vtime_from_timestamp(inode->change_time());

  delete inode->inode();
  delete inode;
}

void	ExtfsNode::set_i_nb(uint64_t i_id)
{
  __i_nb = i_id;
}

uint64_t	ExtfsNode::i_nb() const
{
  return __i_nb;
}

Inode *	ExtfsNode::read_inode()
{
  Inode	*	inode = NULL;
  inodes_t *	i = NULL;

  try
    {
      inode = new Inode(this->__extfs, this->__extfs->SB(),
			this->__extfs->GD());
      i = new inodes_t;
      inode->setInode(i);
      inode->read(__inode_addr, i);
      inode->init();
    }
  catch (vfsError & e)
    {
      std::cerr << "Exception caught in ExtfsNode::extendedAttributes() : "
		<< e.error << std::endl;
      delete i;
      delete inode;
      return NULL;
    }
  catch(std::exception & e)
    {
      std::cerr << "Not enought memory" << std::endl;
      delete i;
      delete inode;
      return NULL;
    }
  return inode;
}
