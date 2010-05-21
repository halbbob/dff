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

#include "bootsector.hpp"

bootSector::bootSector()
{
  //this->bs = new bootsector;
  //  this->parent = parent;
}

bootSector::~bootSector()
{
  //delete this->bs;
}

//XXX -- Check as much values as possible
bool	bootSector::checkBootSectorFields()
{
  // if ( (this->ctx->spec->ssize != 512) &&
  //      (this->ctx->spec->ssize != 1024) &&
  //      (this->ctx->spec->ssize != 2048) &&
  //      (this->ctx->spec->ssize != 4096))
  //   throw("Fatfs: sector size field not valid");
  // if ((this->ctx->spec->csize != 0x01) &&
  //     (this->ctx->spec->csize != 0x02) &&
  //     (this->ctx->spec->csize != 0x04) &&
  //     (this->ctx->spec->csize != 0x08) &&
  //     (this->ctx->spec->csize != 0x10) &&
  //     (this->ctx->spec->csize != 0x20) &&
  //     (this->ctx->spec->csize != 0x40) && 
  //     (this->ctx->spec->csize != 0x80))
  //   throw("Fatfs: cluster size field not valid");
  // if (this->ctx->spec->sectors16 != 0)
  //   this->ctx->spec->totalsector = (uint32_t)this->ctx->spec->sectors16;
  // else if (this->ctx->spec->sectors32 != 0)
  //   this->ctx->spec->totalsector = this->ctx->spec->sectors32;
  // else
  //   throw("Fatfs: total sector count not setted");
  // this->ctx->spec->totalsize = this->ctx->spec->totalsector * this->ctx->spec->ssize;
  // if (this->ctx->spec->sectperfat16 != 0)
  //   this->ctx->spec->sectperfat = (uint32_t)this->ctx->spec->sectperfat16;
  // else if (this->ctx->spec->sectperfat32 != 0)
  //   this->ctx->spec->sectperfat = (uint32_t)this->ctx->spec->sectperfat32;
  // else
  //   throw("Fatfs: sector per fat not setted");
  // this->ctx->spec->fatsize = this->ctx->spec->sectperfat * this->ctx->spec->ssize;
  // if ((this->ctx->spec->fatsize == 0) || (this->ctx->spec->numfat == 0))
  //   throw("Fatfs: size of fat and number of fat not valid");
}

//Further implementation:
// - create translation based on endianness
void	bootSector::bootsectorToCtx()
{
//   this->ctx->spec->ssize = *((uint16_t*)this->bs->ssize);
//   this->ctx->spec->csize = this->bs->csize;
//   this->ctx->spec->reserved = *((uint16_t*)this->bs->reserved);
//   this->ctx->spec->numfat = this->bs->numfat;
//   this->ctx->spec->numroot = *((uint16_t*)this->bs->numroot);
//   this->ctx->spec->sectors16 = *((uint16_t*)this->bs->sectors16);
//   this->ctx->spec->sectperfat16 = *((uint16_t*)this->bs->sectperfat16);
//   this->ctx->spec->prevsect = *((uint32_t*)this->bs->prevsect);
//   this->ctx->spec->sectors32 = *((uint32_t*)this->bs->sectors32);
//   this->ctx->spec->sectperfat32 = *((uint32_t*)this->bs->a.f32.sectperfat32);
//   this->ctx->spec->ext_flag = *((uint16_t*)this->bs->a.f32.ext_flag);
//   this->ctx->spec->fs_ver = *((uint16_t*)this->bs->a.f32.fs_ver);
//   this->ctx->spec->rootclust = *((uint32_t*)this->bs->a.f32.rootclust);
//   this->ctx->spec->fsinfo = *((uint16_t*)this->bs->a.f32.fsinfo);
//   this->ctx->spec->bs_backup = *((uint16_t*)this->bs->a.f32.bs_backup);
// }

// bool	bootSector::DetermineFatType()
// {
//   uint32_t	rootdirsector;

//   rootdirsector = ((this->ctx->spec->numroot * 32) + (this->ctx->spec->ssize - 1)) / this->ctx->spec->ssize;
//   this->ctx->spec->datasector = this->ctx->spec->reserved + (this->ctx->spec->numfat * this->ctx->spec->fatsize) + rootdirsector;
//   this->ctx->spec->totaldatasector = this->ctx->spec->totalsector - (this->ctx->spec->reserved + (this->ctx->spec->numfat * this->ctx->spec->sectperfat) + rootdirsector);
//   this->ctx->spec->totalcluster = this->ctx->spec->totaldatasector / this->ctx->spec->csize;
//   this->ctx->spec->firstfatoffset = this->ctx->spec->reserved * this->ctx->spec->ssize;
  
//   if(this->ctx->spec->totalcluster < 4085)
//     {
//       this->ctx->spec->fattype = 12;
//       this->ctx->spec->rootdiroffset = this->ctx->spec->firstfatoffset + this->ctx->spec->fatsize * this->ctx->spec->numfat;
//       this->ctx->spec->dataoffset = this->ctx->spec->firstfatoffset + this->ctx->spec->fatsize * this->ctx->spec->numfat + rootdirsector * this->ctx->spec->ssize;
//     }
//   else if(this->ctx->spec->totalcluster < 65525)
//     {
//       this->ctx->spec->fattype = 16;
//       this->ctx->spec->rootdiroffset = this->ctx->spec->firstfatoffset + this->ctx->spec->fatsize * this->ctx->spec->numfat;
//       this->ctx->spec->dataoffset = this->ctx->spec->firstfatoffset + this->ctx->spec->fatsize * this->ctx->spec->numfat + rootdirsector * this->ctx->spec->ssize;
//     }
//   else
//     {
//       this->ctx->spec->fattype = 32;
//       this->ctx->spec->rootdiroffset = ((this->ctx->spec->rootclust - 2) * this->ctx->spec->csize) + this->ctx->spec->datasector;
//       this->ctx->spec->dataoffset = this->ctx->spec->reserved * this->ctx->spec->ssize + this->ctx->spec->fatsize * this->ctx->spec->numfat;
//     }
}

// bsctx*		bootSector::getBootSectorContext()
// {
//   return (this->ctx);
// }

void	bootSector::process()
{
  // this->input = input;
  // try
  //   {
  //     this->vfile = this->input->open();
  //     if (this->vfile->read(this->bs, sizeof(bootsector)) == 512)
  // 	{
  // 	  this->fillParameters(params);
  // 	  this->checkSpec(params);
  // 	  this->DetermineFatType(params);
  // 	}
  //     else
  // 	throw("Fatfs: not enough bytes read for boot sector");
  //   }
  // catch (...)
  //   {
  //     throw("Fatfs: error while reading boot sector");
  //   }
}

// Attributes*	bootSector::getAttributes(Node *node)
// {
//   Attributes*	attr;

//   attr = new Attributes();
//   attr->push("size", new Variant(0x200));
//   attr->push("type of FAT", new Variant(this->ctx->spec->fattype));
//   attr->push("oem name", new Variant(this->bs->oemname));
//   attr->push("sector size", new Variant(this->ctx->spec->ssize));
//   attr->push("number of fat", new Variant(this->ctx->spec->numfat));
//   attr->push("allocation block size", new Variant(this->ctx->spec->csize * this->ctx->spec->ssize));
//   attr->push("total sector available", new Variant(this->ctx->spec->totalsector));
//   attr->push("total sectors available for data", new Variant(this->ctx->spec->totaldatasector));
//   attr->push("total cluster", new Variant(this->ctx->spec->totalcluster));
//   attr->push("root directory offset", new Variant(this->ctx->spec->rootdiroffset));
//   if (this->ctx->spec->fattype != 32)
//     attr->push("root directory size", new Variant(this->ctx->spec->rootdirsize));
//   return attr;
// }

bootSectorNode::bootSectorNode(std::string name, mfso* fsobj, Node* parent, Node* origin, uint64_t offset): Node(name, parent, fsobj)
{
  this->origin = origin;
  this->offset = offset;
}

bootSectorNode::~bootSectorNode()
{
}

FileMapping*	bootSectorNode::getFileMapping()
{
  FileMapping*	fm;

  fm = new FileMapping();

  fm->push(this->origin, this->offset, 0x200);
  return fm;
}

Attributes*	bootSectorNode::getAttributes()
{
  Attributes*	attr;

  attr = new Attributes();
  attr->push("size", new Variant(0x200));
  return attr;
}
