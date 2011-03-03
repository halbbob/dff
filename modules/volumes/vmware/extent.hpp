/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
 *
 * Author(s):
 *  MOUNIER Jeremy <jmo@digital-forensic.org>
 *
 */

#ifndef __EXTENT_HPP__
#define __EXTENT_HPP__

#include "vmdk.hpp"
#include "node.hpp"

class	Extent
{
public:

  Extent(Node *nd, uint32_t id);
  ~Extent();

  int	readSparseHeader();
  int	createBackupHeader(int type);

  sparseExtentHeader	header;

  Node		*vmdk;
  VFile		*vfile;

  uint32_t	id;
  uint32_t	version;

  uint32_t	type;

  uint32_t	sectorsPerGDE;
  uint32_t	GDEntries;
  uint32_t	GTEntries;

  uint64_t	sectors;
  uint64_t	sectorsPerGrain;

  uint64_t	sectorGD;
  uint64_t	sectorRGD;

  uint64_t	overheadSectors;

  uint64_t	descriptorSector;
  uint64_t	descriptorSize;

  bool		footer;
  uint16_t	compression;

};

#endif
