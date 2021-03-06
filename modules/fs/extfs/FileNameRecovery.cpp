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

#include <map>
#include <vector>
#include <sstream>

#include "include/FileNameRecovery.h"
#include "include/utils/InodeUtils.h"
#include "include/ExtfsRawDataNode.h"

FileNameRecovery::FileNameRecovery(Journal * journal)
{
  _journal = journal;
}

FileNameRecovery::~FileNameRecovery()
{
  delete _journal;
}

uint8_t	FileNameRecovery::deletedFileNames(uint8_t * tab,
					   uint64_t content_addr,
					   Node * parent,
					   Directory * inode_dir,
					   DirEntry * dir)
{
  DirEntry *	del_dirent = new DirEntry;
  std::string	name;
  Node *	new_node = NULL;
  inodes_t *	_inter = new (inodes_t);
  uint8_t	valid = 0, tmp;

  for (uint64_t pos = content_addr;
       pos < (dir->entry_length() + content_addr - dir->next() - 12); )
    {
      del_dirent->setDir((dir_entry_v2 *)(tab + pos));
      tmp = valid_entry(del_dirent);
      valid = (valid == 2 ? valid : tmp);
      if (!tmp)
	{
	  if (!inode_dir->i_list()->find(del_dirent->inode_value()))
	    inode_dir->i_list()->insert(del_dirent->inode_value());
	  else
	    {
	      pos += del_dirent->next();
	      inode_dir->createNewNode(0, parent,
		       setDirName(del_dirent, tab, pos, true), _inter);
	      continue ;
	    }
	  if (!(name = setDirName(del_dirent, tab, pos, true)).empty())
	    {

#ifdef DIR_DEBUG
	      std::cout << "\tdel file : " << name << std::endl;
#endif
	      if ((new_node = retrieve_inode(inode_dir, del_dirent, parent, name,
					     _inter)))
		{
		  if (((_inter->file_mode & __IFMT) == __IFDIR)
		      && (del_dirent->file_type_v2() == DirEntry::_DIRECTORY))
		    {
		      new_node->setDeleted();
		      Directory * new_dir = new Directory(inode_dir);
		      new_dir->dirContent(new_node, _inter, __addr,
					  del_dirent->inode_value());
		      delete new_dir;
		    }
		}
	    }
	  pos += del_dirent->next();
	  new_node = NULL;
	}
      else
	pos += 4;
      if (pos >= inode_dir->SB()->block_size())
	break ;
    }
  delete _inter;
  delete del_dirent;
  return valid;
}

ExtfsNode *	FileNameRecovery::retrieve_inode(Directory * inode_dir,
						 DirEntry * del_dirent,
						 Node * parent,
						 const std::string & name,
						 inodes_t * _inter)
{
  uint64_t	inode_addr;
  ExtfsNode *	node = NULL;

  __addr = inode_addr = inode_dir->getInodeByNumber(del_dirent->inode_value());
  inode_dir->read(inode_addr, _inter);
  if (inode_dir->is_fucked_up(del_dirent->inode_value()))
    {
      std::ostringstream oss;
      oss << del_dirent->inode_value();
      
      new ExtfsRawDataNode(oss.str(),
	 inode_dir->extfs()->SB()->inodes_struct_size(),
	 inode_dir->extfs()->suspiscious_inodes(), inode_dir->extfs(),
	 inode_addr + inode_dir->extfs()->SB()->offset() - __BOOT_CODE_SIZE);
    }
  
  if (retrieve_inode_direct(_inter, del_dirent->inode_value()))
    node = inode_dir->createNewNode(inode_addr, parent, name, _inter);
  else if (_journal)
    node = recovery(inode_addr / inode_dir->SB()->block_size(),
		    inode_dir, del_dirent, _inter, parent);
  else
    {
      node = inode_dir->createNewNode(0, parent, (char *)name.c_str(), _inter);
      node->setDeleted();
      return NULL;
    }
  if (node)
    {
      node->setDeleted();
      node->set_i_nb(del_dirent->inode_value());
    }
  if (!inode_dir->i_list()->find(del_dirent->inode_value()))
    inode_dir->i_list()->insert(del_dirent->inode_value());
  else
    node = NULL;
  return node;
}

ExtfsNode *   FileNameRecovery::recovery(uint32_t block_number,
					 Directory * dir,
					 DirEntry * dir_e,
					 inodes_t * inode,
					 Node * parent)
{
  std::map<uint32_t, std::vector<uint64_t> >::const_iterator it_l;
  std::vector<uint64_t>	addr_list;
  ExtfsNode *		node = NULL;
  uint64_t		inode_addr = 0;

  it_l = _journal->journal_cache().find(block_number);
  if (it_l == _journal->journal_cache().end())
    {
      node = dir->createNewNode(0, parent, __name, inode);
      node->setDeleted();
      node = NULL;
    }
  else
    {
      addr_list = (*it_l).second;
      if (!addr_list.empty())
	{
	  std::vector<uint64_t>::iterator it = addr_list.begin();
	  uint32_t  nb_i_per_block = dir->SB()->block_size()
	    / dir->SB()->inodes_struct_size();
	  bool	found = false;

	  for (; it != addr_list.end(); it++)
	    {
	      if (!(*it))
		continue ;
	      inode_addr = (*it) * ((uint64_t)_journal->SB()->block_size());
	      if (!((dir_e->inode_value() % nb_i_per_block)))
		inode_addr += (((dir_e->inode_value() % nb_i_per_block) + 1)
			       * dir->SB()->inodes_struct_size());
	      else
		inode_addr += (((dir_e->inode_value() % nb_i_per_block) - 1)
			       * dir->SB()->inodes_struct_size());
	      dir->extfs()->v_seek_read(inode_addr, (void *)inode,
					sizeof(inodes_t));
	      if (inode->block_pointers[0] && !inode->delete_time)
		{
		  if (((inode->file_mode & __IFMT) == __IFREG)
		      && dir_e->file_type_v2() == DirEntry::_REG_FILE)
		    node = dir->createNewNode(inode_addr, parent, __name, inode);
		  else
		    node = dir->createNewNode(0, parent, __name, inode);
		  node->setDeleted();
		  node->set_i_nb(dir_e->inode_value());
		  found = true;
		}
	      if (!found)
		node = dir->createNewNode(0, parent, __name, inode);
	    }
	}
      else
	{
	  node = dir->createNewNode(0, parent, __name, inode);
	  node->setDeleted();
	  node->set_i_nb(dir_e->inode_value());
	  node = NULL;
	}
    }
  return node;
}

bool	FileNameRecovery::retrieve_inode_direct(inodes_t * inode,
						uint32_t inode_nb)
{
  if (inode->block_pointers[0]
      && !_journal->isAllocated(inode_nb, _journal->extfs()->vfile()))
    return true;
  return false;
}

uint8_t    FileNameRecovery::valid_entry(DirEntry * dir)
{
  uint8_t	ret = 0; // 0 : OK, 1 : valide, 2 : invalide
  
  if (!dir)
    return 1;
  else if (!dir->inode_value() && !dir->name_length_v1()
	   && !dir->entry_length())
    return 1;
  else if (dir->inode_value() > _journal->SB()->inodesNumber())
    ret = 2;
  else if ((dir->entry_length() >= _journal->SB()->block_size())
	   || !dir->entry_length())
    ret = 2;
  else if (_journal->SB()->incompatible_feature_flags()
	   & SuperBlockStructure::_DIR_FILE_TYPE)
    {
      if (!dir->name_length_v2())
	ret = 2;
      if (dir->file_type_v2() > 7)
	ret = 2;
    }
  else
    {
      if (!dir->name_length_v1())
	ret = 2;
      if (dir->name_length_v1() > 255)
	ret = 2;
    }
  return ret;
}

bool		FileNameRecovery::valid_name(char * name)
{
  if (name[0] == 0)
    return false;
  if (!strcmp((char *)name, "..") || !strcmp((char *)name, "."))
    return false;
  return true;
}

std::string	FileNameRecovery::setDirName(DirEntry * del_dirent,
					     uint8_t * tab,
					     uint64_t pos,
					     bool del)
{
  std::string name((char *)(tab + pos + 8 * sizeof(uint8_t)),
		   del_dirent->name_length_v2());
  del_dirent->setName((uint8_t *)(name.c_str()));
  if (!valid_name((char *)name.c_str()))
    return (__name = "");
  __name = name;
  return name;
}

Journal * FileNameRecovery::getJournal() const
{
  return _journal;
}
