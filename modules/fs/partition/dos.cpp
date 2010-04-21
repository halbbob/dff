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

Pte::Pte()
{
  this->pte = NULL;
  this->extended = false;
  this->sane = false;
}

Pte::~Pte()
{
}

bool		Pte::isExtended()
{
  return this->extended;
}

bool		Pte::isSane()
{
  return this->sane;
}

void		Pte::set(dos_pte* pte)
{
  this->lba = *((uint32_t*)pte->lba);
  this->size = *((uint32_t*)pte->total_blocks);
  if ((this->lba == 0) && (this->size == 0))
    this->sane = false;
  else
    this->sane = true;
  this->type = pte->type;
  this->extended = is_ext(pte->type);
}

std::string		Pte::Type()
{
  std::string		str_type;

  str_type = partition_types[this->type];
  return str_type;
}

uint32_t		Pte::Size()
{
  return this->size;
}

uint32_t	       Pte::Lba()
{
  return this->lba;
}

DosPartition::DosPartition()
{
  this->vfile = NULL;
  this->node = NULL;
  this->pte = new Pte();
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

// void	Record::sanitizePte(part* pte)
// {
//   uint32_t	lba;
//   uint32_t	total_blocks;
//   std::ostringstream stm;

//   stm << std::hex << std::setiosflags(ios_base::showbase);
//   lba = *((uint32_t*)pte->lba);
//   total_blocks = *((uint32_t*)pte->total_blocks);
//   if ((lba != 0) && (total_blocks != 0))
//     {
//       stm << (int)pte->type;
//       std::cout << "logical block address: " << lba << " total allocated blocks: "
// 		<< total_blocks << " type: " << stm.str() << std::endl;
//     }
// }

void	DosPartition::open(VFile* vfile, uint64_t offset)
{
  if (vfile != NULL)
    {
      try
	{
	  this->vfile = vfile;
	  this->readMbr(offset);
	}
      catch (vfsError e)
	{
	  throw vfsError("Mbr::Mbr() Cannot open node" + e.error);
	}
    }
  else
    throw("provided node is NULL");
}

void	DosPartition::readMbr(uint64_t offset)
{
  dos_partition_record	record;
  uint8_t		i;

  try
    {
      this->vfile->seek(offset);
      this->vfile->read(&record, sizeof(dos_partition_record));
      if (record.signature != 0x55AA)
	;//this->mbr_bad_magic = true;
      for (i = 0; i != 4; i++)
	{
	  this->pte->set(&(record.partitions[i]));
	  if (this->pte->isSane())
	    {
	      std::cout << "lba start: " << this->pte->Lba() << " size: " 
			<< this->pte->Size() << " type: " << this->pte->Type()
			<< std::endl;
	      if (this->pte->isExtended())
		{
		  this->ebr_base = this->pte->Lba();
		  this->readEbr(this->pte->Lba());
		}
	      else
		{
		  this->parts.insert();
		}
	    //this->ebr_base_sect = *((uint32_t*)this->record->partitions[i].lba);
	    }
	}
    }
  catch(vfsError e)
    {
      throw("error while reading partition" + e.error);
    }
}

void	DosPartition::readEbr(uint32_t cur)
{
  dos_partition_record	record;
  uint8_t		i;

  try
    {
      this->vfile->seek((uint64_t)(cur * 512));
      this->vfile->read(&record, sizeof(dos_partition_record));
      for (i = 0; i != 4; i++)
	{
	  this->pte->set(&(record.partitions[i]));
	  if (this->pte->isSane())
	    {
	      std::cout << "lba start: " << this->pte->Lba() << " size: " 
			<< this->pte->Size() << " type: " << this->pte->Type()
			<< std::endl;
	      if (this->pte->isExtended())
		this->readEbr(this->ebr_base + this->pte->Lba());
	    }
	}
    }
  catch(vfsError e)
    {
      throw("error while reading partition" + e.error);
    }
}