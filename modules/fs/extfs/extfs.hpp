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

#ifndef __EXTFS_HPP__
#define __EXTFS_HPP__

#include <iostream>
#include <map>
#include <memory>
#include <typeinfo>

#include "type.hpp"
#include "vfs.hpp"
#include "conf.hpp"
#include "include/ExtfsNode.h"
#include "data_structure/includes/GroupDescriptor.h"
#include "data_structure/includes/extfs_struct/inodes.h"
#include "data_structure/includes/SuperBlock.h"

#define DRIVER_NAME     "extfs"
#define ROOT_INODE	2

class	Extfs : public mfso
{
  /*! \class Extfs.
    \brief Implementation of the API.

    When the \c \b Extfs driver is loaded, the \c \b start() method is called.
  */

public:
  //! Constructor. Initialize some values.
  Extfs();

  //! Destructor. Free resources.
  ~Extfs();

  /*! \brief Start the driver.

    The first called  method when the extfs driver is executed. It lauches the
    execution and catches the eventual exceptions which couls occur when the
    driver is running.

    \param arg the arguments of extfs
  */
  virtual void		start(argument *arg);

  /*! \brief Lauch the driver.
    In this method all the options are parsed and the proper method called.
    \param arg arguments passed to the driver
  */
  void			launch(argument *arg);

  /*! \brief Initialize the driver.
    
    The first thing the \c \b start() method does is trying to read the
    superblock which is located at byte 1024 of the file system.

    Once the super block has been read, the driver can access the \b Group
    \b Descriptor table to locate the position of inode 2, which is the
    root directory inode.

    \param sb_check an option used to force superblock checking
    \param sb_force_addr an option to force the superblock address on the
    vfile.
    \param check_alloc check allocation status
  */
  void			init(const std::string & sb_check,
			     const std::string & sb_force_addr,
			     const std::string & check_alloc);

  /*! \brief Run driver.
    \param root_i_nb the number of the root inode.
  */
  void			run(uint64_t root_i_nb);

  /*! \brief Creates a vfs node.

    The \e \b id of the node is the address of its inode on the vfile. It can
    be set to \e \b 0.

    \param parent the parent node.
    \param name the name of the file.
    \param id the address of the file's inode.
    \param inode the inode of the file.

    \return a pointer to the newly created Node.
  */
  class ExtfsNode *		createVfsNode(Node * parent, std::string  name,
					      uint64_t id, inodes_t * inode);

  /*! \brief vfile accessor.
    \return a pointer to the VFile
  */
  class VFile *			vfile() const;

  /*! \brief Group descriptor.
    \return a pointer to the GroupDescriptor instance.
  */
  class GroupDescriptor *	GD() const;

  /*! \brief Super block.
    \return a pointer to a SuperBlock instance.
  */
  class SuperBlock *		SB() const;

  /*! \brief Seek and read.    

    Written for convenience. Seek to address \e \b addr, then read

    \e \b size bytes and stores the result in \e \b buf.
  */
  void			v_seek_read(uint64_t addr, void * buf, uint64_t size);

  /*! \brief Node accessor.
    \return a pointer to the vfile node.
  */
  Node *		node() const;

  /*! \brief Orphans accessor.
    \return a pointer to the orphans inode node.
  */
  ExtfsNode *		orphans() const;

  /*! \brief Suspicious inode accessor.
    \return a pointer to the suspicious inodes node.
  */
  ExtfsNode *		suspiscious_inodes() const;

  /*! \brief Suspiscious directories accessor.
    \return a pointer to suspiscious directories node.
  */
  ExtfsNode *		suspiscious_dir() const;

  /*! \brief Get arguments.
    
    Get the different arguments from the argument * and catch the exception if
    there is no such argument. This method is templated because arguments can
    be from different types.
    
    \param all_args the list of all arguments
    \param name the name of the argument we want to get.\
    \param arg the ponter to the variable in which we want to store the
    argument we just got.
  */
  template <typename T>
  void	arg_get(argument * all_args, const std::string & name, T arg);

private:
  void		__reserved_inodes();
  void		__add_meta_nodes();
  void		__orphan_inodes();

  class Directory *	__root_dir; // root directory
  class GroupDescriptor* __GD; // group descriptor
  class SuperBlock *	__SB; // superblock
  Node *		__node;
  VFile *		__vfile; // vfs

  Node *	__first_node;
  ExtfsNode *	__fs_node;
  ExtfsNode *	__metadata_node;
  ExtfsNode *	__first_inodes_nodes;
  ExtfsNode *	__orphans_i;
  ExtfsNode *	__suspiscious_i;
  ExtfsNode *	__suspiscious_dir;
};

#endif
