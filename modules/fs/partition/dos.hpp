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

#ifndef __DOS_HPP__
#define __DOS_HPP__

#include "vfile.hpp"
#include "node.hpp"

#define MBR		0x00
#define EBR		0x01

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
  uint8_t		lba[4];
  uint8_t		total_blocks[4];
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
  dos_pte	partitions[4];
  short		signature; //0xAA55
}		dos_partition_record;


typedef struct
{
  uint64_t	start;
  uint64_t	end;
}		partition_info;


class Pte
{
protected:
  dos_pte*	pte;
  bool		extended;
  bool		sane;
  uint32_t	lba;
  uint32_t	size;
  uint8_t	type;
  uint64_t	max;

public:
  Pte();
  ~Pte();
  void		set(dos_pte* pte);
  std::string	Type();
  uint32_t	Lba();
  uint32_t	Size();
  bool		isExtended();
  bool		isSane();
};

// class Record
// {
// public:
//   Record();
//   ~Record();
//   void	read(VFile *vfile, uint64_t offset = 0);
//   //method for reading extended boot record which needs base of the first ebr
//   void	read(VFile* vfile, uint32_t base, uint64_t offset=0);
//   void	open(VFile *vfile, uint8_t type, uint64_t offset = 0);
// };


class DosPartition
{
private:
  vector<partition_info*>	parts;
  Node*				root;
  Node*				origin;
  mfso*				fsobj;
  VFile*			vfile;
  Pte*				pte;
  bool				mbrBadMagic;
  uint32_t			ebr_base;
  uint32_t			partnum;

public:
  DosPartition();
  ~DosPartition();
  //void			setMbrFile(Node* mbr);
  void			open(VFile* vfile, uint64_t offset, Node* root, mfso* fsobj, Node* origin);
  void			readEbr(uint32_t cur);
  void			readMbr(uint64_t offset);
};

#endif
