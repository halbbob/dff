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

#ifndef __RECORD_HPP__
#define __RECORD_HPP__

#include "vfile.hpp"
#include "node.hpp"

#include "nodes.hpp"

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
}		        part;


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
  part		partitions[4];
  short		signature; //0xAA55
}		record;

// class PartitionEntry
// {
// public:
//   PartitionEntry(Node* origin, uint64_t offset);
//   ~PartitionEntry();
// };

class Record
{
private:
  VFile*	vfile;
  Node*		parent;
public:
  PartitionEntry*	getPartition(uint8_t number);
  Record(Node* origin, uint64_t offset);
  ~Record();
};

#endif
