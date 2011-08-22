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

#ifndef BLK_LIST_
#define BLK_LIST_

#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif


#include "../data_structure/includes/GroupDescriptor.h"
#include "../data_structure/includes/SuperBlock.h"
#include "vfile.hpp"

class	BlkList
{
public :
  BlkList(GroupDescriptor * GD, SuperBlock * SB, VFile * vfile);
  ~BlkList();

  void	stat(const std::string & blk_list);
  bool	blk_allocation_status(uint64_t blk_nb, bool display = false);

private :
  GroupDescriptor *	__GD;
  VFile *	__vfile;
  SuperBlock *	__SB;
  uint64_t	__begin;
  uint64_t	__end;
  uint64_t	__bit_addr;
  uint8_t	__dec;
  uint16_t	__group;
};

#endif
