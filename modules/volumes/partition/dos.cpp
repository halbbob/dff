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

#include "dos.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

char partition_types[256][128] = 
{
  "Empty",
  "DOS 12-bit FAT",
  "XENIX root",
  "XENIX /usr",
  "DOS 3.0+ 16-bit FAT (up to 32M)",
  "DOS 3.3+ Extended Partition",
  "DOS 3.31+ 16-bit FAT (over 32M)",
  "QNX2.x pre-1988 (see below under IDs 4d-4f)",
  "QNX 1.x and 2.x (qny)",
  "QNX 1.x and 2.x (qnz)",
  "OPUS",
  "WIN95 OSR2 FAT32",
  "WIN95 OSR2 FAT32, LBA-mapped",
  "Unknown",
  "WIN95: DOS 16-bit FAT, LBA-mapped",
  "WIN95: Extended partition, LBA-mapped",
  "OPUS (?)",
  "Hidden DOS 12-bit FAT",
  "Configuration/diagnostics partition",
  "Unknown",
  "Hidden DOS 16-bit FAT &lt;32M",
  "Unknown",
  "Hidden DOS 16-bit FAT &gt;=32M",
  "Hidden IFS (e.g., HPFS)",
  "AST SmartSleep Partition",
  "Unused",
  "Unknown",
  "Hidden WIN95 OSR2 FAT32",
  "Hidden WIN95 OSR2 FAT32, LBA-mapped",
  "Unknown",
  "Hidden WIN95 16-bit FAT, LBA-mapped",
  "Unknown",
  "Unused",
  "Unused",
  "Unused",
  "Reserved",
  "NEC DOS 3.x",
  "Unknown",
  "Reserved",
  "RouterBOOT kernel partition",
  "Unknown",
  "Unknown",
  "AtheOS File System (AFS)",
  "SyllableSecure (SylStor)",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unknown",
  "Reserved",
  "NOS",
  "Reserved",
  "Reserved",
  "JFS on OS/2 or eCS",
  "Reserved",
  "Unknown",
  "THEOS ver 3.2 2gb partition",
  "THEOS ver 4 spanned partition",
  "THEOS ver 4 4gb partition",
  "THEOS ver 4 extended partition",
  "PartitionMagic recovery partition",
  "Hidden NetWare",
  "Unknown",
  "Unknown",
  "PICK",
  "PPC PReP (Power PC Reference Platform) Boot",
  "Windows 2000 dynamic extended partition marker",
  "Linux native (sharing disk with DRDOS)",
  "GoBack partition",
  "EUMEL/Elan",
  "EUMEL/Elan",
  "EUMEL/Elan",
  "EUMEL/Elan",
  "Unknown",
  "AdaOS Aquila (Withdrawn)",
  "Unknown",
  "Oberon partition",
  "QNX4.x",
  "QNX4.x 2nd part",
  "Oberon partition",
  "Native Oberon (alt)",
  "Novell",
  "Microport SysV/AT",
  "Disk Manager 6.0 Aux3",
  "Disk Manager 6.0 Dynamic Drive Overlay (DDO)",
  "EZ-Drive",
  "DM converted to EZ-BIOS",
  "VNDI Partition",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unknown",
  "Priam EDisk",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unknown",
  "SpeedStor",
  "Unknown",
  "Unix System V (SCO, ISC Unix, UnixWare, ...), Mach, GNU Hurd",
  "Novell Netware 286, 2.xx",
  "Novell Netware 386, 3.xx or 4.xx",
  "Novell Netware SMS Partition",
  "Novell",
  "Novell",
  "Novell Netware 5+, Novell Netware NSS Partition",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unknown",
  "??",
  "Unknown",
  "DiskSecure Multi-Boot",
  "Reserved",
  "V7/x86",
  "Reserved",
  "Scramdisk partition",
  "IBM PC/IX",
  "Reserved",
  "VNDI Partition",
  "XOSL FS",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unknown",
  "Unused",
  "Unused",
  "MINIX until 1.4a",
  "Mitac disk manager",
  "Linux swap",
  "Linux native partition",
  "Hibernation partition",
  "Linux extended partition",
  "FAT16 volume set",
  "NTFS volume set",
  "Linux plaintext partition table",
  "Unknown",
  "Linux Kernel Partition (used by AiR-BOOT)",
  "Legacy Fault Tolerant FAT32 volume",
  "Legacy Fault Tolerant FAT32 volume using BIOS extd INT 13h",
  "Free FDISK 0.96+ hidden Primary DOS FAT12 partitition",
  "Linux Logical Volume Manager partition",
  "Unknown",
  "Free FDISK 0.96+ hidden Primary DOS FAT16 partitition",
  "Free FDISK 0.96+ hidden DOS extended partitition",
  "Free FDISK 0.96+ hidden Primary DOS large FAT16 partitition",
  "Amoeba",
  "Amoeba bad block table",
  "MIT EXOPC native partitions",
  "CHRP ISO-9660 filesystem",
  "Free FDISK 0.96+ hidden Primary DOS FAT32 partitition",
  "Datalight ROM-DOS Super-Boot Partition",
  "DCE376 logical drive",
  "Free FDISK 0.96+ hidden Primary DOS FAT16 partitition (LBA)",
  "Free FDISK 0.96+ hidden DOS extended partitition (LBA)",
  "Unknown",
  "Unknown",
  "ForthOS partition",
  "BSD/OS",
  "Laptop hibernation partition",
  "HP Volume Expansion (SpeedStor variant)",
  "Unknown",
  "HP Volume Expansion (SpeedStor variant)",
  "HP Volume Expansion (SpeedStor variant)",
  "BSD/386, 386BSD, NetBSD, FreeBSD",
  "HP Volume Expansion (SpeedStor variant)",
  "NeXTStep",
  "Mac OS-X",
  "NetBSD",
  "Olivetti Fat 12 1.44MB Service Partition",
  "GO! partition",
  "Unknown",
  "Unknown",
  "ShagOS filesystem",
  "MacOS X HFS",
  "BootStar Dummy",
  "QNX Neutrino Power-Safe filesystem",
  "QNX Neutrino Power-Safe filesystem",
  "QNX Neutrino Power-Safe filesystem",
  "HP Volume Expansion (SpeedStor variant)",
  "Unknown",
  "Corrupted Windows NT mirror set (master), FAT16 file system",
  "BSDI BSD/386 filesystem",
  "BSDI BSD/386 swap partition",
  "Unknown",
  "Unknown",
  "Boot Wizard hidden",
  "Acronis backup partition",
  "Unknown",
  "Solaris 8 boot partition",
  "New Solaris x86 partition",
  "DR-DOS/Novell DOS secured partition",
  "DRDOS/secured (FAT-12)",
  "Hidden Linux",
  "Hidden Linux swap",
  "DRDOS/secured (FAT-16, &lt; 32M)",
  "DRDOS/secured (extended)",
  "Windows NT corrupted FAT16 volume/stripe set",
  "Syrinx boot",
  "Reserved for DR-DOS 8.0+",
  "Reserved for DR-DOS 8.0+",
  "Reserved for DR-DOS 8.0+",
  "DR-DOS 7.04+ secured FAT32 (CHS)/",
  "DR-DOS 7.04+ secured FAT32 (LBA)/",
  "CTOS Memdump?",
  "DR-DOS 7.04+ FAT16X (LBA)/",
  "DR-DOS 7.04+ secured EXT DOS (LBA)/",
  "Multiuser DOS secured partition",
  "Old Multiuser DOS secured FAT12",
  "Unknown",
  "Unknown",
  "Old Multiuser DOS secured FAT16 &lt;32M",
  "Old Multiuser DOS secured extended partition",
  "Old Multiuser DOS secured FAT16 &gt;=32M",
  "Unknown",
  "CP/M-86",
  "Unknown",
  "Powercopy Backup",
  "KDG Telemetry SCPU boot",
  "Unknown",
  "Hidden CTOS Memdump?",
  "Dell PowerEdge Server utilities (FAT fs)",
  "BootIt EMBRM",
  "Unknown",
  "DOS access or SpeedStor 12-bit FAT extended partition",
  "Unknown",
  "DOS R/O or SpeedStor",
  "SpeedStor 16-bit FAT extended partition &lt; 1024 cyl.",
  "Unknown",
  "Storage Dimensions SpeedStor",
  "Unknown",
  "LUKS",
  "Unknown",
  "Unknown",
  "BeOS BFS",
  "SkyOS SkyFS",
  "Unused",
  "Indication that this legacy MBR is followed by an EFI header",
  "Partition that contains an EFI file system",
  "Linux/PA-RISC boot loader",
  "Storage Dimensions SpeedStor",
  "DOS 3.3+ secondary partition",
  "Reserved",
  "Prologue single-volume partition",
  "Prologue multi-volume partition",
  "Storage Dimensions SpeedStor",
  "DDRdrive Solid State File System",
  "Unknown",
  "pCache",
  "Bochs",
  "VMware File System partition",
  "VMware Swap partition",
  "Linux raid partition with autodetect using persistent superblock",
  "Linux Logical Volume Manager partition (old)",
  "Xenix Bad Block Table"
};

std::string	uint32ToStr(uint32_t ui32)
{
  ostringstream os;

  os << ui32;
  return os.str();
}

std::string	uint64ToStr(uint64_t ui64)
{
  ostringstream os;

  os << ui64;
  return os.str();
}

DosPartitionNode::DosPartitionNode(std::string name, uint64_t size, Node* parent, fso* fsobj, Node* origin):  Node(name, size, parent, fsobj)
{
  this->origin = origin;
  this->setFile();
}

DosPartitionNode::~DosPartitionNode()
{
}

void	DosPartitionNode::fileMapping(FileMapping* fm)
{
  uint64_t	offset;

  offset = ((uint64_t)this->base + this->pte->lba) * 512;
  if (( this->size() - this->origin->size()) > 0)
  {
     fm->push(0, this->origin->size(), this->origin, offset);
     fm->push(this->origin->size(), this->size() - this->origin->size());
  }
  else
    fm->push(0, this->size(), this->origin, offset);
}

void	DosPartitionNode::extendedAttributes(Attributes* attr)
{
  std::string		str_type;
  std::string		startsect;
  uint64_t		startoffset;

  if ((this->type & LOGICAL) == LOGICAL)
    {
      //memset(startsect, 0, 64);
      startsect = uint32ToStr(this->base) + "+" + uint32ToStr(this->pte->lba);
      //sprintf(startsect, "%u+%d", this->base, this->pte->lba);
      attr->push("starting sector", new Variant(std::string(startsect)));
      startoffset = ((uint64_t)this->base + (uint64_t)this->pte->lba) * 512;
      attr->push("starting offset", new Variant(startoffset));
    }
  else
    {
      attr->push("starting sector", new Variant(this->pte->lba));
      attr->push("starting offset", new Variant((uint64_t)this->pte->lba * 512));
    }
  attr->push("total sectors", new Variant(this->pte->total_blocks));
  attr->push("total size (bytes)", new Variant((uint64_t)this->pte->total_blocks * 512));
  attr->push("entry offset", new Variant(this->entryoffset));
  if (this->pte->status == 0x80)
    attr->push("status", new Variant("bootable"));
  else if (this->pte->status == 0x00)
    attr->push("status", new Variant("non bootable"));
  else
    attr->push("status", new Variant("invalid"));
  str_type = "";
  if ((this->type & PRIMARY) == PRIMARY)
    str_type += "(primary";
  if ((this->type & LOGICAL) == LOGICAL)
    str_type += "(logical";
  if ((this->type & EXTENDED) == EXTENDED)
    str_type += "(extended";
  if ((this->type & HIDDEN) == HIDDEN)
    str_type += " | hidden)";
  else
    str_type += ") ";
  str_type += partition_types[pte->type];
  attr->push("type", new Variant(str_type));
}

void	DosPartitionNode::setCtx(uint64_t entryoffset, dos_pte* pte, uint8_t type, uint32_t base)
{
  this->pte = pte;
  this->entryoffset = entryoffset;
  this->type = type;
  this->base = base;
}

DosPartition::DosPartition()
{
  this->vfile = NULL;
  this->root = NULL;
  this->origin = NULL;
  this->partnum = 1;
}

DosPartition::~DosPartition()
{
  if (this->vfile != NULL)
    {
      try
	{
	  this->vfile->close();
	  delete this->vfile;
	}
      catch(vfsError e)
	{
	  throw vfsError("Partition error while closing file" + e.error);
	}
    }
}

void	DosPartition::open(VFile* vfile, uint64_t offset, Node* root, mfso* fsobj, Node* origin)
{
  if (vfile != NULL)
    {
      try
	{
	  this->root = root;
	  this->origin = origin;
	  this->fsobj = fsobj;
	  this->vfile = vfile;
	  this->readMbr(offset);
	}
      catch (vfsError e)
	{
	  throw vfsError("[PARTITION] Error while processing MBR\n" + e.error);
	}
    }
  else
    {
      throw vfsError("[PARTITION] provided vfile is NULL, can't read\n");
    }
}

dos_pte*	DosPartition::toPte(uint8_t* buff)
{
  dos_pte*	pte;
  uint32_t	lba;
  uint32_t	total_blocks;

  memcpy(&lba, buff+8, 4);
  memcpy(&total_blocks, buff+12, 4);
  if ((lba == 0) && (total_blocks == 0))
    return NULL;
  else
    {
      pte = new dos_pte;
      memcpy(pte, buff, 8);
      pte->lba = lba;
      pte->total_blocks = total_blocks;
      return pte;
    }
}

void	DosPartition::createNode(dos_pte* pte, uint64_t offset, uint8_t type, uint32_t base)
{
  DosPartitionNode*	node;
  uint64_t		size;
  std::string		partname;

  partname =  "part" + uint32ToStr(this->partnum);
  this->partnum += 1;
  size = (uint64_t)(pte->total_blocks) * 512;
  node = new DosPartitionNode(partname, size, this->root, this->fsobj, this->origin);
  node->setCtx(offset, pte, type, base);
}

void	DosPartition::readMbr(uint64_t offset)
{
  dos_partition_record	record;
  uint8_t		i;
  dos_pte*		pte;

  try
    {
      this->vfile->seek(offset);
      if (this->vfile->read(&record, sizeof(dos_partition_record)) > 0)
	{
	  if (record.signature != 0x55AA)
	    {
	      throw vfsError("[PARTITION] Not a valid MBR, Signature (0x55AA) does not match\n");
	    }
	  for (i = 0; i != 4; i++)
	    {
	      pte = this->toPte(record.partitions+(i*16));
	      if (pte != NULL)
		{
		  if (is_ext(pte->type))
		    {
		      this->createNode(pte, offset + 446 + i * 16, EXTENDED);
		      this->ebr_base = (uint64_t)(pte->lba);
		      this->readEbr(pte->lba);
		    }
		  else
		    this->createNode(pte, offset + 446 + i * 16, PRIMARY);
		}
	    }
	}
    }
  catch(vfsError e)
    {
      throw vfsError("[PARTITION] error while reading MBR\n" + e.error);
    }
}

void	DosPartition::readEbr(uint32_t cur, uint32_t shift)
{
  dos_partition_record	record;
  uint8_t		i;
  dos_pte*		pte;
  uint64_t		offset;

  try
    {
      offset = this->vfile->seek((uint64_t)(cur)*512);
      if (this->vfile->read(&record, sizeof(dos_partition_record)) > 0)
	{
	  for (i = 0; i != 4; i++)
	    {
	      pte = this->toPte(record.partitions+(i*16));
	      if (pte != NULL)
		{
		  if (is_ext(pte->type))
		    {
		      if ((this->ebr_base + pte->lba) != cur)
			this->readEbr(this->ebr_base + (uint64_t)(pte->lba), pte->lba);
		    }
		  else
		    {
 		      if (i > 2)
			this->createNode(pte, offset + 446 + i * 16, LOGICAL|HIDDEN, this->ebr_base + shift);
		      else
			this->createNode(pte, offset + 446 + i * 16, LOGICAL, this->ebr_base + shift);
		    }
		}
	    }
	}
    }
  catch(vfsError e)
    {
      throw vfsError("[PARTITION] error while reading EBR\n" + e.error);
    }
}
