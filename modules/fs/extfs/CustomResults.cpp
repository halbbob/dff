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

#include <string>
#include <sstream>

#include "include/CustomResults.h"
#include "include/FsStat.h"

CustomResults::CustomResults()
{
}

CustomResults::~CustomResults()
{
}

void    CustomResults::set(Attributes * attr, Inode * inode)
{
  std::map<std::string, class Variant *> m;
  std::ostringstream sig;
  std::ostringstream  auth_uid_gid;

  sig << std::hex << inode->SB()->signature();
  m["Signature"] = new Variant(std::string("0x") + sig.str());
  m["Creator OS"] =  new Variant(getOs(inode->SB()->creator_os()));
  m["File system ID"] =  new Variant(getFSID(inode->SB()->file_system_ID()));
  m["Error handling"] = new Variant(getErrorHandling(inode->SB()->error_handling_method()));
  std::string     vol_name = (char *)inode->SB()->volume_name();
  m["Volume name"] =  new Variant(vol_name);
  std::string     path_mount = (char *)inode->SB()->path_last_mount();
  m["Path to last mount"] =  new Variant(path_mount);
  m["Algorithm usage bitmap"] = new Variant(inode->SB()->algorithm_bitmap());
  m["Current mount count"] =  new Variant(inode->SB()->current_mount_count());
  m["Max mount count"] = new Variant(inode->SB()->max_mount_count());
  m["File system"] =  new Variant(m);
  m["Orphan inode list"] = new Variant(inode->SB()->orphan_node_list());
  m["Major version"] = new Variant(inode->SB()->major_version());
  m["Minor version"] =  new Variant(inode->SB()->minor_version());
  m.clear();

  m["Block size (in Bytes)"] = new Variant(inode->SB()->block_size());
  m["Inode size (in bytes)"] = new Variant(inode->SB()->inodes_struct_size());
  m["Block number"] =  new Variant(inode->SB()->blocks_number());
  m["Inodes number"] =  new Variant(inode->SB()->inodesNumber());
  m["Blocks per group"] =  new Variant(inode->SB()->block_in_groups_number());
  m["Inodes per group"] = new Variant(inode->SB()->inodes_in_group_number());
  m["Group number"] =
    new Variant(inode->SB()->blocks_number() / inode->SB()->block_in_groups_number());
  m["Fragment size"] =  new Variant(inode->SB()->fragment_size());
  m["group descriptor size"]
    = new Variant((inode->SB()->getSuperBlock()->s_desc_size ?
		   inode->SB()->getSuperBlock()->s_desc_size : 32));
  attr->push("File system size", new Variant(m));
  m.clear();

  m["Last mount time"] = add_time(inode->SB()->last_mount_time());
  m["Last written time"] = add_time(inode->SB()->last_written_time());
  m["Last consistency check time"] = add_time(inode->SB()->l_consistency_ct());
  m["Forced consistency interval"] = add_time(inode->SB()->consitency_forced_interval());
  attr->push("Time", new Variant(m));
  m.clear();

  auth_uid_gid << inode->SB()->gid_reserved_block() <<  " / "
	       << inode->SB()->uid_reserved_block();
  m["Reserved block GID / UID"] =  new Variant(auth_uid_gid.str());
  m["First non reserved inode"] = new Variant(inode->SB()->f_non_r_inodes());
  m["Preallocate file blocks"] =  new Variant(inode->SB()->preallocate_blocks_files());
  m["Preallocate directory blocks"] =  new Variant(inode->SB()->preallocate_block_dir());
  m["Reserved blocks"] = new Variant(inode->SB()->r_blocks_number());
  m["Unallocated blocks"] =  new Variant(inode->SB()->u_blocks_number());
  m["Unallocated inodes"] = new Variant(inode->SB()->u_inodes_number());
  m["Group 0's block"] =  new Variant(inode->SB()->first_block());
  attr->push("Content", new Variant(m));
  m.clear();

  std::string jr_id = (char *)inode->SB()->journal_id();
  m["Journal ID"] =  new Variant(jr_id);
  m["Journal inode"] = new Variant(inode->SB()->journal_inode());
  m["journal device"] =  new Variant(inode->SB()->journal_device());
  attr->push("Journal", new Variant(m));
  m.clear();

  attr->push("Flags", getFlags(inode->SB()));

  m["Compatible features"] = getCompatibleFeatures(inode->SB());
  m["Incompatible features"] = getIncompatibleFeatures(inode->SB());
  m["Read only features"] = getReadOnlyFeatures(inode->SB());
  attr->push("Features", new Variant(m));
  m.clear();

  FsStat	fs_stat;
  fs_stat.attr_stat(inode->SB(), inode->extfs()->vfile(), attr);
  //  m[layout]
}

Variant *    CustomResults::add_time(time_t t)
{
#ifndef WIN32
  std::string ti(t ? ctime(&t) : "NA\n");
  ti[ti.size() - 1] = 0;
#else
	std::string ti = "fixme";
#endif
  return new Variant(ti);
}

std::string CustomResults::getFlags(uint16_t fs_state)
{
  std::string     flags = "";
  if (fs_state & SuperBlock::_FS_STATE_CLEAN)
    flags = flags + "Clean - ";
  if (fs_state & SuperBlock::_FS_HAS_ERRORS)
    flags = flags + "Errors - ";
  if (fs_state & SuperBlock::_ORPHAN_RECOVERY)
    flags = flags + "Orphan recovery ";
  return flags;
}

Variant * CustomResults::getFlags(const SuperBlock * SB)
{
  std::list<class Variant *>	l;
  uint32_t	fs_state = SB->fs_state();
  
  if (fs_state & SuperBlock::_FS_STATE_CLEAN)
    l.push_back(new Variant(std::string("Clean")));
  if (fs_state & SuperBlock::_FS_HAS_ERRORS)
    l.push_back(new Variant(std::string("Errors")));
  if (fs_state & SuperBlock::_ORPHAN_RECOVERY)
    l.push_back(new Variant(std::string("Orphan recovery")));
  if (l.empty())
    l.push_back(new Variant(std::string("(None)")));
  return new Variant(l);
}

std::string CustomResults::getErrorHandling(uint16_t error_handling_method)
{
  std::string err = "None";
  if (error_handling_method == SuperBlock::_ERROR_HANDLING_CONTINUE)
    err = "Continue";
  else if (error_handling_method == SuperBlock::_RO_REMOUNT)
    err = "Read-only remount";
  else if (error_handling_method == SuperBlock::_PANIC)
    err = "Panic";
  return err;
}

std::string CustomResults::getOs(uint32_t creator_os)
{
  std::string os = "Unknown";
  if (creator_os == SuperBlock::_OS_LINUX)
    os = "Linux";
  else if (creator_os == SuperBlock::_OS_GNU_HURD)
    os = "Gnu HURD";
  else if (creator_os == SuperBlock::_OS_MASIX)
    os = "Masix";
  else if (creator_os == SuperBlock::_OS_FREE_BSD)
    os = "Free BSD";
  else if (creator_os == SuperBlock::_OS_LITES)
    os = "Lites";
  return os;
}

std::string CustomResults::getCompatibleFeatures(uint32_t c_f_flags)
						 
{
  std::string feat = "";
  if (c_f_flags & SuperBlock::_COMP_PDIR)
    feat +=  "Directory preallocation - ";
  if (c_f_flags & SuperBlock::_COMP_AFS_INODE)
    feat += "Afs server - ";
  if (c_f_flags & SuperBlock::_COMP_HAS_JOURNAL)
    feat += "Journal - ";
  if (c_f_flags & SuperBlock::_COMP_EXT_ATTR)
    feat += "Ext attr - ";
  if (c_f_flags & SuperBlock::_COMP_CAN_RESIZE)
    feat += "Resize - ";
  if (c_f_flags & SuperBlock::_COMP_DIR_HASH_INDEX)
    feat += "Hash index";
  return feat;
}

Variant *	CustomResults::getCompatibleFeatures(const SuperBlock * SB)
{
  std::list<class Variant *>	l;
  uint32_t			c_f_flags;

  c_f_flags = SB->compatible_feature_flags();
  if (c_f_flags & SuperBlock::_COMP_PDIR)
    l.push_back(new Variant(std::string("Directory preallocation")));
  if (c_f_flags & SuperBlock::_COMP_AFS_INODE)
    l.push_back(new Variant(std::string("Afs sercer")));
  if (c_f_flags & SuperBlock::_COMP_HAS_JOURNAL)
    l.push_back(new Variant(std::string("Using journal")));
  if (c_f_flags & SuperBlock::_COMP_EXT_ATTR)
    l.push_back(new Variant(std::string("Extended attributes")));
  if (c_f_flags & SuperBlock::_COMP_CAN_RESIZE)
    l.push_back(new Variant(std::string("Inodes resize")));
  if (c_f_flags & SuperBlock::_COMP_DIR_HASH_INDEX)
    l.push_back(new Variant(std::string("Directories index")));
  return new Variant(l);
}

std::string CustomResults::getIncompatibleFeatures(uint32_t i_f_flags)
{
  std::string feat = "";

  if (i_f_flags & SuperBlock::_COMPRESSION)
    feat += "Compression - ";
  if (i_f_flags & SuperBlock::_DIR_FILE_TYPE)
    feat += "File type in dir entries - ";
  if (i_f_flags & SuperBlock::_NEEDS_RECOVERY)
    feat += "Need recovery - ";
  if (i_f_flags & SuperBlock::_JOURNAL_DEVICE)
    feat += "Use journal device - ";
  if (i_f_flags & SuperBlock::_META_BG)
    feat += "Meta block group - ";
  if (i_f_flags & SuperBlock::_EXTENTS)
    feat += "Support for extents - ";
  if (i_f_flags & SuperBlock::_64BITS)
    feat += "64 bits support - ";
  if (i_f_flags & SuperBlock::_FLEX_BG)
    feat += "Flex block group - ";
  if (i_f_flags & SuperBlock::_EA_INODE)
    feat += "EA in inodes - ";
  if (i_f_flags & SuperBlock::_DIRENT_DATA)
    feat += "Data in dirents";
  return feat;
}

Variant * CustomResults::getIncompatibleFeatures(const SuperBlock * SB)
{
  std::list<class Variant *>	l;
  uint32_t			i_f_flags;

  i_f_flags = SB->incompatible_feature_flags();
  if (i_f_flags & SuperBlock::_COMPRESSION)
    l.push_back(new Variant(std::string("Compression")));
  if (i_f_flags & SuperBlock::_DIR_FILE_TYPE)
    l.push_back(new Variant(std::string("File type in directory entries")));
  if (i_f_flags & SuperBlock::_NEEDS_RECOVERY)
    l.push_back(new Variant(std::string("Needs recovery")));
  if (i_f_flags & SuperBlock::_JOURNAL_DEVICE)
    l.push_back(new Variant(std::string("Use journal device")));
  if (i_f_flags & SuperBlock::_META_BG)
    l.push_back(new Variant(std::string("Meta block group")));
  if (i_f_flags & SuperBlock::_EXTENTS)
    l.push_back(new Variant(std::string("Support for extents")));
  if (i_f_flags & SuperBlock::_64BITS)
    l.push_back(new Variant(std::string("64 bits support")));
  if (i_f_flags & SuperBlock::_FLEX_BG)
    l.push_back(new Variant(std::string("Flex block group")));
  if (i_f_flags & SuperBlock::_EA_INODE)
    l.push_back(new Variant(std::string("EA in inodes")));
  if (i_f_flags & SuperBlock::_DIRENT_DATA)
    l.push_back(new Variant(std::string("Data in dirents")));
  return new Variant(l);
}

std::string CustomResults::getReadOnlyFeatures(uint32_t r_o_flags)
{
  std::string feat = "";
  if (r_o_flags & SuperBlock::_SPARSE_SUPERBLOCK)
    feat += "Sparse superblock - ";
  if (r_o_flags & SuperBlock::_LARGE_FILE)
    feat += "Large file - ";
  if (r_o_flags & SuperBlock::_B_TREES)
    feat += "Directories B-Trees - ";
  if (r_o_flags & SuperBlock::_HUGE_FILE)
    feat += "Huge files - ";
  if (r_o_flags & SuperBlock::_GD_CSUM)
    feat += "Group descriptor checksum - ";
  if (r_o_flags & SuperBlock::_DIR_NLINK)
    feat += "Directory nlink - ";
  if (r_o_flags & SuperBlock::_EXTRA_ISIZE)
    feat += "Extra inode size";
  return feat;
}

Variant * CustomResults::getReadOnlyFeatures(const SuperBlock * SB)
{
  std::list<class Variant *>	l;
  uint32_t			i_f_flags;

  i_f_flags = SB->ro_features_flags();
  if (i_f_flags & SuperBlock::_SPARSE_SUPERBLOCK)
    l.push_back(new Variant(std::string("Sparse superblock")));
  if (i_f_flags & SuperBlock::_LARGE_FILE)
    l.push_back(new Variant(std::string("Large files")));
  if (i_f_flags & SuperBlock::_B_TREES)
    l.push_back(new Variant(std::string("Directories B-Trees")));
  if (i_f_flags & SuperBlock::_HUGE_FILE)
    l.push_back(new Variant(std::string("Huge files")));
  if (i_f_flags & SuperBlock::_GD_CSUM)
    l.push_back(new Variant(std::string("Group descriptor checksum")));
  if (i_f_flags & SuperBlock::_DIR_NLINK)
    l.push_back(new Variant(std::string("Directory nlink")));
  if (i_f_flags & SuperBlock::_EXTRA_ISIZE)
    l.push_back(new Variant(std::string("Extra inode size")));
  return new Variant(l);
}

std::string CustomResults::getFSID(const uint8_t * fs_id)
{
  std::ostringstream id;
  for (int i = 0; i < 16; ++i)
    id << std::hex << (int)fs_id[i];
  return "0x" + id.str();
}
