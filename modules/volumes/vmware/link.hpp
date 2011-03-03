/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
 *
 * Author(s):
 *  MOUNIER Jeremy <jmo@digital-forensic.org>
 *
 */

#ifndef __LINK_HPP__
#define __LINK_HPP__

#include "vmdk.hpp"
#include "extent.hpp"

#include "diskDescriptor.hpp"

class	Link
{
public:
  Link(diskDescriptor	*desc, int type, Node *vmdkroot);
  ~Link();

  int			listExtents();
  //  int			readSparseHeader(extentInfo *extent);
  int			addExtent(Node *vmdk);
  bool			isBase();
  uint64_t		volumeSize();

  vector<Extent*>	getExtents();
  string		getCID();
  string		getPCID();


  void			setLinkStorageVolumeSize();

  //  int			createBackupHeader(int type, extentInfo *extent);

private:

  int			_type;

  uint64_t		_storageVolumeSize;

  Node			*_vmdkroot;

  diskDescriptor	*_descriptor;

  string		_cid;
  string		_pcid;

  bool			_baseLink;

  vector<Extent*>	_extents;

};

#endif
