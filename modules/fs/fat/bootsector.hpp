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

#ifndef __BOOTSECTOR_HPP__
#define __BOOTSECTOR_HPP__

#include "node.hpp"
#include "vfile.hpp"

typedef struct
{
  uint8_t	f1[3];
  char		oemname[8];
  uint8_t	ssize[2];       /* sector size in bytes */
  uint8_t	csize;          /* cluster size in sectors */
  uint8_t	reserved[2];    /* number of reserved sectors for boot sectors */
  uint8_t	numfat;         /* Number of FATs */
  uint8_t	numroot[2];     /* Number of Root dentries */
  uint8_t	sectors16[2];   /* number of sectors in FS */
  uint8_t	f2[1];
  uint8_t	sectperfat16[2];        /* size of FAT */
  uint8_t	f3[4];
  uint8_t	prevsect[4];    /* number of sectors before FS partition */
  uint8_t	sectors32[4];   /* 32-bit value of number of FS sectors */

  /* The following are different for fat12/fat16 and fat32 */
  union
  {
    struct
    {
      uint8_t	f5[3];
      uint8_t	vol_id[4];
      uint8_t	vol_lab[11];
      uint8_t	fs_type[8];
      uint8_t	f6[448];
    } f16;
    struct
    {
      uint8_t	sectperfat32[4];
      uint8_t	ext_flag[2];
      uint8_t	fs_ver[2];
      uint8_t	rootclust[4];   /* cluster where root directory is stored */
      uint8_t	fsinfo[2];      /* TSK_FS_INFO Location */
      uint8_t	bs_backup[2];   /* sector of backup of boot sector */
      uint8_t	f5[12];
      uint8_t	drvnum;
      uint8_t	f6[2];
      uint8_t	vol_id[4];
      uint8_t	vol_lab[11];
      uint8_t	fs_type[8];
      uint8_t	f7[420];
    } f32;
  } a;

  uint8_t	magic[2];       /* MAGIC for all versions */

} bootsector;


class bootSector//: public Metadata
{
private:
  Node*		parent;
  void		bootsectorToCtx();
  bool		checkBootSectorFields();
  bool		DetermineFatType();

public:
  bootSector();
  ~bootSector();
  void	process();
//   virtual class FileMapping*	getFileMapping(class Node* node);
//   virtual class Attributes*	getAttributes(class Node* node);
};

class bootSectorNode: public Node
{
private:
  uint64_t	offset;
  Node*		origin;
public:
  bootSectorNode(std::string name, mfso* fsobj, Node* parent, Node* readon, uint64_t offset);
  ~bootSectorNode();
  class FileMapping*	getFileMapping();
  class Attributes*	getAttributes();
};

#endif
