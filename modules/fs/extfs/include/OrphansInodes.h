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

#ifndef ORPHANS_INODES_H_
#define ORPHANS_INODES_H_

#include "vfile.hpp"
#include "TwoThreeTree.hpp"
#include "../data_structure/includes/SuperBlock.h"
#include "../data_structure/includes/GroupDescriptor.h"
#include "../extfs.hpp"

class	OrphansInodes
{
public :
  OrphansInodes(TwoThreeTree * parsed_i_list);
  ~OrphansInodes();

  void	load(class Extfs * extfs);

private :
  TwoThreeTree *	__i_list;
};

#endif
