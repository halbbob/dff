/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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

#ifndef __DOS_HPP__
#define __DOS_HPP__

#include "exceptions.hpp"
#include "vfile.hpp"
#include "node.hpp"
#include "partition.hpp"

#define is_ext(t) ((((t) == 0x05) || ((t) == 0x0F) || ((t) == 0x85)) ? 1 : 0)

typedef struct		
{
  uint8_t		status;//0x80 = bootable, 0x00 = non-bootable, other = invalid
  uint8_t		start_head;
  uint8_t	        start_sector; //sector in bit 5-0, bits 9-8 of cylinders are in bits 7-6...
  uint8_t		start_cylinder; // bits 7-0
  uint8_t		type;
  uint8_t		end_head;
  uint8_t		end_sector; //sector in bit 5-0, bits 9-8 of cylinders are in bits 7-6...
  uint8_t		end_cylinder; //bits 7-0
  uint32_t		lba;
  uint32_t		total_blocks;
}		        dos_pte;

/*
"code" field is usually empty in extended boot record but could contain
another boot loader or something volontary hidden...  
this field could also contain IBM Boot Manager starting at 0x18A.

Normally, there are only two partition entries in extended boot records
followed by 32 bytes of NULL bytes. It could be used to hide data or even
2 other partition entries.
*/
typedef struct
{
  uint8_t	code[440];
  union
  {
    struct
    {
      uint8_t	disk_signature[4];
      uint8_t	padding[2];
    }mbr;
    struct
    {
      uint8_t	code[6];
    }ebr;
  } a;
  uint8_t	partitions[64];
  short		signature; //0xAA55
}		dos_partition_record;

class DosPartitionNode: public Node
{
private:
  Node*		origin;
public:
  uint64_t	entryoffset;
  dos_pte*	pte;
  uint32_t	base;
  uint8_t	type;
  DosPartitionNode(std::string name, uint64_t size, Node* parent, class Partition* fsobj, Node* origin);
  ~DosPartitionNode();
  void		setCtx(uint64_t entryoffset, dos_pte* pte, uint8_t type, uint32_t base=0);
  virtual void	fileMapping(class FileMapping* fm);
  virtual Attributes		 _attributes(void);
};

#define PRIMARY		0x01
#define EXTENDED	0x02
#define	LOGICAL		0x04
#define HIDDEN		0x08

class DosPartition
{
private:
  //vector<partition_info*>	parts;
  Node*				root;
  Node*				origin;
  class Partition*		fsobj;
  VFile*			vfile;
  //Pte*				pte;
  bool				mbrBadMagic;
  uint32_t			ebr_base;
  uint32_t			partnum;
  std::map<std::string, Variant*>	res;
  dos_pte*			toPte(uint8_t* buff);
  DosPartitionNode*				createNode(dos_pte* pte, uint64_t offset, uint8_t type, uint32_t base=0);

public:
  DosPartition();
  ~DosPartition();
  Attributes		result();
  void			open(VFile* vfile, uint64_t offset, Node* root, Partition* fsobj, Node* origin);
  void			readEbr(std::list<Variant* >* vlist, uint32_t cur, uint32_t shift=0);
  void			readMbr(uint64_t offset);
};

#endif
