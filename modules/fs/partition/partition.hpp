/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __PARTITION_HPP__
#define __PARTITION_HPP__

#include "mfso.hpp"
#include "vfile.hpp"

#include "dos.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>

class Partition : public mfso
{
private:
  std::ostringstream		Result;
  Node				*parent;
  Node				*__root;
  DosPartition*			dos;
//   int				SetResult();
//   int				getParts();
//   Node				*createPart(Node *parent, unsigned int sector_start, unsigned int size);
//   void				readMbr();
//   void				readExtended(Node *parent, unsigned int start, unsigned int next_lba);
//   bool				isExtended(char type);
//   string			hexilify(char type);

public:
  Partition();
  ~Partition();

  virtual void		start(argument* arg);
};

#endif
