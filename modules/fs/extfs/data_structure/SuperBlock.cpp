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

#include <sstream>

#include "includes/SuperBlock.h"
#include "include/ExtfsShiftNode.h"
#include "../extfs.hpp"

SuperBlock::SuperBlock() : SuperBlockStructure()
{
  _offset = __BOOT_CODE_SIZE;
}

SuperBlock::~SuperBlock()
{
}

void    SuperBlock::init(uint64_t fs_size, VFile * vfile, results * res,
                         const std::string & sb_check,
                         const std::string & sb_force_addr)
  throw(vfsError)
{
  //seek and read boot code : 1024 bytes
  read(vfile, __BOOT_CODE_SIZE);

  if (sb_force_addr != "1024")
    force_addr(vfile, sb_force_addr);

  // check the super block validity
  if ((sb_check == "yes") || (!sanity_check(fs_size)))
    {
      if (sb_check == "yes")
	std::cout << "Forcing superblock check : "
	  "trying to locate a backup." << std::endl;
      else
	std::cerr << "The superblock signature doesn't match 0x53ef. "
	  "Trying to locate a backup..." << std::endl;
      if (!(sigfind(fs_size, vfile)))
	throw vfsError("Error while reading Extfs superblock : "
		       "Could not verify the validity or find valid backups.\n");
      else
        {
	  most_recent_backup(vfile);
	  file_system_sanity();
        }
    }
}

void    SuperBlock::force_addr(VFile * vfile, const std::string & addr)
{
  // convert string to uint64_t
  std::istringstream iss(addr);
  iss >> _offset;

  /* seek and read to the super block at _offset, or throw if an exception is
     caught */
  try
    {
      vfile->seek(_offset);
      vfile->read((void *)getSuperBlock(), __BOOT_CODE_SIZE);
    }
  catch(vfsError & e)
    {
      throw ;
    }
}

bool    SuperBlock::sanity_check(uint64_t fs_size) const
{
    if (signature() != __SB_SIG)
        return false;
    if (!block_size())
        return false;
    if (creator_os() != _OS_FREE_BSD && creator_os() != _OS_GNU_HURD
        && creator_os() != _OS_LINUX && creator_os() != _OS_LITES
        && creator_os() != _OS_MASIX)
        return false;
    if (u_inodes_number() > inodesNumber()
        || inodes_in_group_number() > inodesNumber())
        return false;
    return true;
}

bool    SuperBlock::sigfind(uint64_t fs_size, VFile * vfile)
{
  super_block_t_	sig[4];
  bool			possible_sb_found = false;
  uint64_t		previous_hit = 0;
  uint16_t		array_size = sizeof(sig); //should be 4096 bytes

  _offset = 0; //offset of signature in the superblock
  while (_offset < fs_size)
    {
      uint16_t  read_size = ((_offset + array_size) > fs_size ?
			     array_size - (fs_size - _offset) : array_size);

      vfile->seek(_offset);
      vfile->read((void *)sig, read_size);

      for (uint8_t i = 0; i < (read_size / 1024); ++i)
        {
	  if (sig[i].signature == __SB_SIG)
            {
	      std::cout << "Hit : " << (_offset) / 1024
			<< "\tPrevious : " << previous_hit / 1024 << " ("
			<< (_offset - previous_hit) / 1024 << ")";
	      if (sanity_check(fs_size))
                {
		  possible_sb_found = true;
		  _backup_list.insert(std::make_pair(_offset,
						     last_written_time()));
		  std::cout << "\t -> Possibly valid." << std::endl;
                }
	      else
		std::cout << "\t -> Invalid." << std::endl;
	      previous_hit = _offset;
            }
	  _offset += sizeof(super_block_t_);
        }
    }
  vfile->seek(_offset - __BOOT_CODE_SIZE);
  return possible_sb_found;
}

uint64_t        SuperBlock::most_recent_backup(VFile * vfile) throw(vfsError)
{
  uint64_t	offset = 0;
  uint32_t      prev_date = 0;

  if (_backup_list.empty())
    throw vfsError("SuperBlock::most_recent_backup() : "
		   "the backup list is empty.\n");

  std::map<uint64_t, uint32_t>::iterator it = _backup_list.begin(),
    it_end = _backup_list.end();
  for (; it != it_end; it++)
    if ((*it).second > prev_date)
      {
	prev_date = (*it).second;
	offset = (*it).first;
      }
  std::cout << "The most recent superblock backup has been located at offset "
	    << offset << "." << std::endl;
  _offset = offset;
  return read(vfile, offset);
}

void            SuperBlock::file_system_sanity()
{
  // if we are in group 0, this is not a backup, no need to check anything.
  if (!current_block_group())
    return ;
  
  // otherwise, this is a backup and we need to verify some data consistency.
  if ((current_block_group() * block_in_groups_number())
      != (_offset /  block_size()))
    std::cout << "WARNING : the file system doesn't seem to be valid." << std::endl
	      << "\t -> Are you sure you are analyzing an EXT file system?"
	      << std::endl;
  else
    std::cout << "The file system seems to be valid." << std::endl;
  return ;
}

uint32_t          SuperBlock::read(VFile * vfile, uint64_t offset)
{
  vfile->seek(offset);
  return vfile->read(getSuperBlock(), sizeof(super_block_t_));
}

uint32_t          SuperBlock::group_number() const
{
  uint32_t  gr_nb = blocks_number() / block_in_groups_number();
  if (blocks_number() % block_in_groups_number())
    ++gr_nb;
  return gr_nb;
}

uint64_t    SuperBlock::offset() const
{
  return _offset;
}

ExtfsShiftNode *	SuperBlock::build_fs(Extfs * extfs) throw (vfsError)
{
  ExtfsShiftNode *	shift = NULL;
  return shift;
}
