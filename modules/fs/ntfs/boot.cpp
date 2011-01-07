/* 
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * 
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
 *  Christophe Malinge <cma@digital-forensic.org>
 *
 */

#include "common.hpp"
#include "boot.hpp"

#include <sstream>

Boot::Boot(VFile *vfile)
{
  _clusterSize = 0;
  _mftEntrySize = 0;
  _vfile = vfile;
  _indexRecordSize = 0;
}

Boot::~Boot()
{
  if (_bootBlock)
    delete _bootBlock;
}

bool	Boot::isPow2(int num)
{
 int	i = num / 2;

 while (i > 1)
   {
     if (num != i * 2)
       return false;
     num /= 2;
     i = num / 2;
   }
 if (i == 1 && i * 2 != num)
   return false;
 return true;
}

BootBlock	*Boot::getBootBlock()
{
  return _bootBlock;
}

void	Boot::setBootBlock(BootBlock *bootBlock)
{
  _bootBlock = bootBlock;
  _clusterSize = _bootBlock->bytePerSector * _bootBlock->sectorPerCluster;
  if (isPow2(_bootBlock->clusterIndexRecord))
    _indexRecordSize = _bootBlock->clusterIndexRecord * _clusterSize;
  else {
    DEBUG(INFO, "Invalid index record size in BootSector\n");
    ;
  }
}

/**
 * Check
 *  - BOOT_MEDIA_DESCRIPTOR_ID in mediaDescriptorId
 *  - BOOT_FAT_NTFS_SIGNATURE in signature
 */
bool			Boot::isBootBlock(uint64_t offset)
{
  std::ostringstream	expectedMediaID;
  BootBlock		*bootBlock = new BootBlock;

  _vfile->seek(offset);
  _vfile->read(bootBlock, BOOT_BLOCK_SIZE);
  expectedMediaID << BOOT_MEDIA_DESCRIPTOR_ID;
  if ((expectedMediaID.str() == std::string(bootBlock->mediaDescriptorId))
      && (bootBlock->signature == BOOT_FAT_NTFS_SIGNATURE)) {
    setBootBlock(bootBlock);

    DEBUG(INFO, "Boot block found\n");
    DEBUG(INFO, "\tByte per sector: %u\n", bootBlock->bytePerSector);
    DEBUG(INFO, "\tSector per cluster: %u\n", bootBlock->sectorPerCluster);
#if __WORDSIZE == 64
    DEBUG(INFO, "\tNumber of sector: %lx\n", bootBlock->numberOfSector);
    DEBUG(INFO, "\tStart Mft: 0x%lx\n", bootBlock->startMft);
    DEBUG(INFO, "\tStart Mft 16b Mirror: 0x%lx\n", bootBlock->startMftMirr);
#else
    DEBUG(INFO, "\tNumber of sector: %llx\n", bootBlock->numberOfSector);
    DEBUG(INFO, "\tStart Mft: 0x%llx\n", bootBlock->startMft);
    DEBUG(INFO, "\tStart Mft 16b Mirror: 0x%llx\n", bootBlock->startMftMirr);
#endif
    DEBUG(INFO, "\tCluster Mft record: %u\n", bootBlock->clusterMftRecord);
    if (isPow2(bootBlock->clusterMftRecord)) {
      _mftEntrySize = bootBlock->clusterMftRecord * _clusterSize;
      DEBUG(INFO, "\tMFT Entry size: %u\n", _mftEntrySize);
    }
    else {
      DEBUG(INFO, "\tMFT Entry size not valid in bootblock");
      DEBUG(INFO, "\tTODO: search for it");
      ;
    }
    DEBUG(INFO, "\tCluster Index record: %u\n", bootBlock->clusterIndexRecord);
    DEBUG(INFO, "\tCluster Size: %u\n", _clusterSize);
  }
  else {
    delete bootBlock;;
    return false;
  }
  return true;
}

/* TODO
searchForBootBlock()
{

}
*/
