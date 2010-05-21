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

#ifndef __FAT_HPP__
#define __FAT_HPP__

#include "node.hpp"
#include "vfile.hpp"

class FileAllocationTable
{
private:
  uint8_t		type;
  uint8_t		total;
  uint32_t		size;
  uint64_t		firstfatoffset;
  VFile*		vfile;
  Node*			parent;

public:
  FileAllocationTable();
  //FileAllocationTable(fsinfo* ctx, mfso* fsobj, Node* n);
  ~FileAllocationTable();
  void			setParent(Node* parent);
  void			setNumberOfFat(uint8_t total);
  void			setFirstFatOffset(uint64_t firstfatoffset);
  void			setFatType(uint8_t type);
  void			setFatSize(uint32_t size);
  uint32_t		getNextCluster(uint32_t current, uint8_t which=0);
  std::list<uint32_t>	getClusterChain(uint32_t start, uint8_t which=0);
  std::list<uint32_t>	getFreeClusters(uint8_t which=0);
  uint32_t		getFreeClusterCount(uint8_t which=0);
  std::list<uint32_t>	getAllocatedClusters(uint8_t which=0);
  uint32_t		getAllocatedClusterCount(uint8_t which=0);
  // virtual class FileMapping*	getFileMapping(class Node* node){};
  // virtual class Attributes*	getAttributes(class Node* node){};
};

#endif
