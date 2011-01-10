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

#include <string.h>
#include <sstream>
#include <memory>

#include "extfs.hpp"
#include "include/Option.h"
#include "include/ExtfsNode.h"
#include "include/ExtfsRawDataNode.h"
#include "include/ExtfsSymLinkNode.h"
#include "include/ExtfsShiftNode.h"
#include "data_structure/includes/Inode.h"
#include "include/FileNameRecovery.h"
#include "include/OrphansInodes.h"

Extfs::Extfs()
  : mfso("extfs"), __root_dir(NULL), __node(NULL), __vfile(NULL),
    __first_node(NULL), __fs_node(NULL), __metadata_node(NULL),
    __first_inodes_nodes(NULL), __orphans_i(NULL)
{
  __SB = NULL;
}

Extfs::~Extfs()
{
  delete __SB;
  delete __GD;
  delete __root_dir;
}

void    Extfs::start(argument * arg)
{
  try
    {
      launch(arg);
    }
  catch (envError & e)
    {
      std::cerr << "Extfs::start() : envError Exception caught : \n\t ->"
		<< e.error << std::endl;
    }
  catch (vfsError & e)
    {
      std::cerr << "Extfs::start() :  vfsError exeption caught :"
		<< std::endl << "\t -> " << e.error << std::endl;
      throw e;
    }
  catch (std::exception & e)
    {
      std::cerr << "Extfs::start() : std::exception caught :\n\t -> "
		<< e.what() << std::endl;
    }
  catch (...)
    {
      std::cerr << "Extfs::start() : unknown exception caught."
		<< std::endl;
    }
}

void		Extfs::launch(argument * arg)
{
  bool		sb_check = false;
  std::string	sb_force_addr("1024");
  bool		run_driver;
  std::string	check_alloc("");
  uint64_t	root_i_nb = ROOT_INODE;
  Option *	opt;

  // get arguments, initialize and run.
  arg_get(arg, "parent", &__node);
  arg_get(arg, "SB_addr", &sb_force_addr);
  arg_get(arg, "SB_check", &sb_check);
  //  arg_get(arg, "check_alloc", &check_alloc);
  //  sb_check = !sb_check;

  // initialization
  this->init((sb_check ? "yes" : "no"),
	     (sb_force_addr.empty() ? "1024" : sb_force_addr), check_alloc);
  opt = new Option(arg, __SB, __vfile, __GD);
  opt->parse(this);

  // parsing file system
  arg_get(arg, "parse_fs", &run_driver);
  if (run_driver)
    {
      std::string	orphans("");
      std::string	root_inode("");

      arg_get(arg, "i_orphans", &orphans);
      arg_get(arg, "root_inode", &root_inode);
      if (!root_inode.empty())
	{
	  std::istringstream	iss(root_inode);
	  iss >> root_i_nb;
	}
      run(root_i_nb);

      /* parse orphans inode (i.e. inodes which are not part of the file system
	 content) */
      if (!(orphans.empty()) && (orphans == "yes"))
	__orphan_inodes();
      __root_dir->clean();
      this->registerTree(__node, __first_node);
    }
}

void		Extfs::init(const std::string & sb_check,
			    const std::string & sb_force_addr,
			    const std::string & check_alloc)
{
  __SB = new SuperBlock;
  __vfile = __node->open();
  __SB->init(__node->size(), __vfile, NULL, sb_check, sb_force_addr);
  __GD = new GroupDescriptor(__SB, __SB->block_size());
  __GD->init(__SB->block_size(), __vfile, __SB->group_number(),
	     (!check_alloc.empty() && check_alloc == "yes"));
  __alloc_inode = __SB->inodesNumber() - __SB->u_inodes_number();
  __nb_parsed_inode = 0;
}

void		Extfs::run(uint64_t root_i_nb)
{
  uint64_t	addr;
  inodes_t	inode;

  __root_dir = new Directory(this, __SB, __GD);
  addr = __root_dir->getInodeByNumber(root_i_nb);
  __root_dir->setInode(&inode);
  __root_dir->dir_init();
  __root_dir->i_list()->insert(root_i_nb);
  __root_dir->read(addr, &inode);
  __first_node = new ExtfsNode("Extfs", 0, NULL, this, 0, true);
  __fs_node = new ExtfsNode("File system", 0, __first_node, this, addr);
  __fs_node->set_i_nb(root_i_nb);
  __metadata_node = new ExtfsNode("Metadata", 0, __first_node, this, 0);
  __suspiscious_i = new ExtfsNode("Suspiscious inodes", 0, __first_node,
				  this, 0);
  __suspiscious_dir = new ExtfsNode("Suspiscious directory", 0, __first_node,
				    this, 0);
  __root_dir->dirContent(__fs_node, (inodes_t *)__root_dir->inode(),
			 addr, root_i_nb);
  __add_meta_nodes();
  __reserved_inodes();
  //  __root_dir->i_list()->clear();
  this->stateinfo = "Finished";
}

void	Extfs::v_seek_read(uint64_t addr, void * buf, uint64_t size)
{
  __vfile->seek(addr + __SB->offset() - __BOOT_CODE_SIZE);
  __vfile->read(buf, size);
}

class ExtfsNode *	Extfs::createVfsNode(Node * parent, std::string name,
					     uint64_t id, inodes_t * inode)
{
  uint64_t	size = 0;

  if (!inode)
    return NULL;
  if ((inode->file_mode & __IFMT) == __IFLNK)
    {
      size = inode->lower_size;
      /*
	ExtfsSymLinkNode * node
	= new ExtfsSymLinkNode(name, size, parent, this, id);
	node->setLink();
      */
      ExtfsNode * node = new ExtfsNode(name, 0, parent, this, id);
      return node;
    }
  else if (id && ((inode->file_mode & __IFMT) == __IFREG))
    {
      size = inode->lower_size;
      ExtfsNode * node = new ExtfsNode(name, size, parent, this, id);
      node->setFile();
      return node;
    }
  ExtfsNode * node = new ExtfsNode(name, size, parent, this, id);
  return node;
}

Node *	Extfs::node() const
{
  return __node;
}

class GroupDescriptor *	Extfs::GD() const
{
  return __GD;
}

class SuperBlock *	Extfs::SB() const
{
  return __SB;
}

class VFile *	Extfs::vfile() const
{
  return __vfile;
}

ExtfsNode *	Extfs::orphans() const
{
  return __orphans_i;
}

ExtfsNode *	Extfs::suspiscious_inodes() const
{
  return __suspiscious_i;
}

ExtfsNode *	Extfs::suspiscious_dir() const
{
  return __suspiscious_dir;
}

void		Extfs::__reserved_inodes()
{
  Inode *	inode = new Inode(this, __SB, __GD);
  inodes_t *	inode_s = new inodes_t;	

  __first_inodes_nodes = new ExtfsNode("Reserved inodes", 0, __first_node,
				       this, 0);
  inode->setInode(inode_s);
  for (unsigned int i = 1; i < __SB->f_non_r_inodes(); ++i)
    if ((i != ROOT_INODE) && (i != __SB->journal_inode()))
      {
	uint64_t		addr;
	ExtfsNode *		node;
	std::ostringstream	oss;

	addr = inode->getInodeByNumber(i);
	inode->read(addr, inode_s);
	oss << i;
	node = createVfsNode(__first_inodes_nodes, oss.str(), addr,
			     (inodes_t *)inode->inode());
	node->set_i_nb(i);
      }
}

void			Extfs::__add_meta_nodes()
{
  ExtfsRawDataNode *	BootCode;
  ExtfsRawDataNode *	SBNode;
  ExtfsRawDataNode *	GDNode;
  ExtfsNode *		node;
  uint64_t		gd_size;
  uint64_t		addr;

  if (__SB->journal_inode()) // create a journal node (if there is a journal)
    {
      addr = __root_dir->getInodeByNumber(__SB->journal_inode());
      node = createVfsNode(__metadata_node, "Journal", addr,
       (inodes_t *)__root_dir->recovery()->getJournal()->inode());
       node->set_i_nb(__SB->journal_inode());
    }
  BootCode = new ExtfsRawDataNode("Boot code area", 1024, __metadata_node,
				  this, __SB->offset() - __BOOT_CODE_SIZE);
  SBNode = new ExtfsRawDataNode("Superblock", 1024, __metadata_node, this,
				1024 + __SB->offset() - __BOOT_CODE_SIZE);
  gd_size = __SB->group_number() * __GD->GD_size();
  gd_size += (__SB->block_size() - gd_size % __SB->block_size());
  GDNode = new ExtfsRawDataNode("Group descriptor table", gd_size,
				__metadata_node, this,
				__GD->groupDescriptorAddr());
}

void	Extfs::__orphan_inodes()
{
  OrphansInodes *	orphans_i = new OrphansInodes(__root_dir->i_list());
  this->__orphans_i = new ExtfsNode("Orphans inodes", 0, __first_node, this, 0);
  orphans_i->load(this);
}

template <typename T>
void        Extfs::arg_get(argument * all_args, const std::string & name, T arg)
{
  try
    {
      all_args->get(name, arg);
    }
  catch (vfsError & e)
    {
      std::cerr << "Could not load " << name << " parameter" << std::endl;
    } 
  catch (...)
    {
    }
}
