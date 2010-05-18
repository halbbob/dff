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

#ifndef __FSINFO_HPP__
#define __FSINFO_HPP__

typedef struct
{
  uint16_t	ssize;
  uint8_t	csize;
  uint16_t	reserved;
  uint8_t	numfat;
  uint16_t	numroot;
  uint16_t	sectors16;
  uint16_t	sectperfat16;
  uint32_t	prevsect;
  uint32_t	sectors32;

  //Only for Fat32
  uint32_t	sectperfat32;
  uint16_t	ext_flag;
  uint16_t	fs_ver;
  uint32_t	rootclust;
  uint16_t	fsinfo;
  uint16_t	bs_backup;

  //total sector count
  uint32_t	totaldatasector;
  uint32_t	totalsector;
  uint32_t	sectperfat;
  uint32_t	totalcluster;
  
  //precomputed values based on bytes per sector and cluster size
  uint64_t	firstfatoffset;
  uint64_t	rootdiroffset;
  uint32_t	rootdirsize;
  uint64_t	dataoffset;
  uint32_t	datasector;
  uint32_t	fatsize;
  uint64_t	totalsize;
  //fat type based on computation
  uint8_t	fattype;
}		fatctx;

class FatContext
{
private:
  mfso*	fsobj;
public:
  fatctx*			spec;
  FileAllocationTable*		fat;
  FatContext(mfso* fsobj);
  ~FatContext();
  Node*		allocateNode(Node* parent){};
};

#endif
