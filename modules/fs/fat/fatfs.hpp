/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __FATFS_HPP__
#define __FATFS_HPP__

#include "bootsector.hpp"
#include "fat.hpp"
#include "mfso.hpp"
#include "node.hpp"
#include "fsinfo.hpp"

class Fatfs : public mfso
{
private:
  Node*			parent;
  Node*			root;
  bootSector*		bootsector;
  FileAllocationTable*	fat;
  
public:
  Fatfs();
  ~Fatfs();

  virtual void		start(argument *arg);
  void			setContext(argument* arg);
  void			process(fsinfo* );
};

#endif
