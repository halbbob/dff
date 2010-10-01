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

#include <map>
#include <sstream>

#include "data_structure/includes/ExtendedAttr.h"
#include "data_structure/includes/Ext4Extents.h"
#include "include/MfsoAttrib.h"

MfsoAttrib::MfsoAttrib()
{
}

MfsoAttrib::~MfsoAttrib()
{
}

void	MfsoAttrib::setAttrs(Inode * inode, Attributes * attr, uint64_t i_nb,
			     uint64_t i_addr)
{
  if (inode->delete_time())
      attr->push("Deletion time",
		 new Variant(vtime_from_timestamp(inode->delete_time())));
  if (!i_nb)
    return ;
  attr->push("Number", new Variant(i_nb));

  std::ostringstream	oss;
  oss << i_addr << " ( 0x" << std::hex << i_addr << ") ";

  attr->push("Address", new Variant(oss.str()));
  attr->push("Group", new Variant(inode->groupNumber(i_nb)));
  attr->push("UID / GID",
     new Variant(inode->uid_gid(inode->lower_uid(), inode->lower_gid())));
  attr->push("File mode", new Variant(inode->type_mode(inode->file_mode())));
  attr->push("Set UID / GID ?",
	     new Variant(inode->set_uid_gid(inode->file_mode())));
  if (inode->flags() & 0x80000)
    attr->push("Inode uses extents", new Variant(std::string("yes")));
  else
    attr->push("Inode uses extents", new Variant(std::string("no")));
  attr->push("Link number", new Variant(inode->link_coun()));
  attr->push("NFS generation number",
	     new Variant(inode->generation_number_nfs()));
  attr->push("Fragment block",
	     new Variant(inode->fragment_addr()));
  attr->push("Fragment index",
	     new Variant(inode->fragment_index()));
  attr->push("Fragment size",
	     new Variant(inode->fragment_size()));
  if (inode->file_acl_ext_attr())
    {
      __add_xtd_attr(inode, attr);
      __add_acl(inode, attr);
    }
  if (inode->type_mode(inode->file_mode())[0] != 'l') // file is not a symlink
    __block_pointers(inode, attr);
  else
    __symlink_path(inode, attr);
}

vtime *	MfsoAttrib::vtime_from_timestamp(time_t UNIX_timestamp)
{
 

  time_t tmp = UNIX_timestamp;
  #ifndef WIN32
  
   tm  * t;
   t = gmtime(&tmp);

   vtime * at = new vtime(t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
			 t->tm_hour, t->tm_min, t->tm_sec, 0); 
  
  
  #else
    vtime * at = new vtime(0, 0, 0,0, 0, 0, 0); 
  
  #endif

 
  return at;
}

void	MfsoAttrib::__add_xtd_attr(Inode * inode, Attributes * attr)
{
  ExtendedAttr *	xtd_attr;

  attr->push("Extended attribute header",
	     new Variant(inode->file_acl_ext_attr()));

  xtd_attr = new ExtendedAttr(inode->file_acl_ext_attr(),
			      inode->SB()->block_size());
  xtd_attr->init(inode->extfs());
  std::map<xattr_name_entries *,
    std::pair<std::string, std::string> >::const_iterator user;

  std::string	xtd = "Inode extended attributes";
  std::map<std::string, class Variant * >	m;

  user = xtd_attr->getUserXAttr().begin();
  for (; user != xtd_attr->getUserXAttr().end(); user++)
    m["user." + (*user).second.first] = new Variant((*user).second.second);
  attr->push(xtd, new Variant(m));
}

void	MfsoAttrib::__add_acl(Inode * inode, Attributes * attr)
{
  attr->push(std::string("Posix ACL"), new Variant(std::string("Not handled yet. \
			Please use the --istat option.")));
  // TODO
}

void		MfsoAttrib::__block_pointers(Inode * inode, Attributes * attr)
{
  uint32_t	block_number;
  uint32_t	tmp = inode->SB()->block_size() / 4;
  uint32_t	i;
  std::map<std::string, class Variant *>	m;
  std::list<Variant *>	blk_list;

  if (inode->flags() & 0x80000) // extents, do nothing for now
    __extents_block(inode, attr);
  else
    {
      uint32_t	previous_block = 0, blk;

      m["Direct"] = NULL;
      m["Single indirect"] = NULL;
      m["Double indirect"] = NULL;
      m["Triple indirect"] = NULL;
      for (i = 0; i <= (tmp * tmp); ++i)
	{
	  block_number = inode->goToBlock(i);
	  if (!previous_block)
	    blk = block_number;
	  else if (block_number != (previous_block + 1))
	    {
	      std::ostringstream	oss;

	      oss << blk << " -> " << previous_block;
	      blk_list.push_back(new Variant(oss.str()));
	      blk = previous_block;
	    }	    
	  previous_block = block_number;
	  if ((i == 12) && !blk_list.empty())
	    {
	      m["Direct"] = new Variant(blk_list);
	      blk_list.clear();
	    }
	  else if (((i - 12) == tmp) && !blk_list.empty() )
	    {
	      if (!blk_list.empty())
		{
		  m["Single indirect"] = new Variant(blk_list);
		  blk_list.clear();
		}
	    }
	  else if (((i - 12 - tmp) == (tmp * tmp)) && !blk_list.empty())
	    {
	      if (!blk_list.empty())
		{
		  m["Double indirect"] = new Variant(blk_list);
		  blk_list.clear();
		}
	    }
	}
    }
  attr->push(std::string("Block pointers"), new Variant(m));
}

void	MfsoAttrib::__symlink_path(Inode * inode, Attributes * attr)
{
  std::string	path("");
  uint16_t	size;

 // max path length contained directly in the inode
  if ((size = inode->lower_size()) < 60)
    path.insert(0, (char *)&inode->block_pointers()[0], size);
  else
    {
      uint8_t *	tab;
      uint64_t	addr;

      tab = (uint8_t *)operator new(size * sizeof(uint8_t));
      addr = inode->block_pointers()[0] * inode->SB()->block_size();
      inode->extfs()->v_seek_read(addr, tab, size);
      path.insert(0, (char *)tab, size);
      attr->push("Link block", new Variant(inode->block_pointers()[0]));
    }
  attr->push("Link target", new Variant(path));
}

void	MfsoAttrib::__extents_block(Inode * inode, Attributes * attr)
{
  Ext4Extents	extents(NULL);
  std::list<std::pair<uint16_t, uint64_t> >   ext_list;
  std::list<std::pair<uint16_t, uint64_t> >::const_iterator it;
  std::map<std::string, class Variant *> m;
  std::list<class Variant *>	blk_l;

  extents.push_extended_blocks(inode);
  ext_list = extents.extents_list();
  it = ext_list.begin();
  while (it != ext_list.end())
    {
      std::ostringstream oss;

      oss << (*it).second;
      oss << " -> ";
      oss << (*it).first + (*it).second - 1;
      blk_l.push_back(new Variant(oss.str()));
      it++;
    }
  if (!blk_l.empty())
    attr->push("Extent blocks", new Variant(blk_l));
  else
    attr->push("Extent blocks", NULL);
}
