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

#ifndef __FAT_HPP__
#define __FAT_HPP__

#include "node.hpp"
#include "vfile.hpp"
#include "bootsector.hpp"

#define FATFS_12_MASK   0x00000fff
#define FATFS_16_MASK   0x0000ffff
#define FATFS_32_MASK   0x0fffffff

class FileAllocationTable
{
private:
  VFile*		vfile;
  Node*			origin;
  class BootSector*	bs;
  //std::vector<uint32_t>	freeclusterscountbyfat;

public:
  FileAllocationTable();
  ~FileAllocationTable();
  uint64_t		clusterOffsetInFat(uint64_t cluster, uint8_t which);
  uint32_t		cluster12(uint64_t offset, uint32_t current);
  uint32_t		cluster16(uint64_t offset);
  uint32_t		cluster32(uint64_t offset);
  void			setContext(Node* origin, BootSector *bs);
  uint32_t		nextCluster(uint32_t current, uint8_t which=0);
  std::vector<uint64_t>	clusterChainOffsets(uint32_t cluster, uint8_t which=0);
  std::vector<uint32_t>	clusterChain(uint32_t start, uint8_t which=0);
  bool			isFreeCluster(uint32_t cluster, uint8_t which);
  std::vector<uint64_t>	listFreeClustersOffset(uint8_t which=0);
  std::vector<uint32_t>	listFreeClusters(uint8_t which=0);
  uint32_t		freeClustersCount(uint8_t which=0);
  std::list<uint32_t>	listAllocatedClusters(uint8_t which=0);
  uint32_t		allocatedClustersCount(uint8_t which=0);
  std::list<uint32_t>	listBadClusters(uint8_t which=0);
  std::list<uint32_t>	listBadClustersCount(uint8_t which=0);
  uint64_t		clusterToOffset(uint32_t cluster);
  uint32_t		offsetToCluster(uint64_t offset);
  void			diffFats();
};

#endif
