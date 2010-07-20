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

#ifndef __FATNODES_HPP__
#define __FATNODES_HPP__

#include "fatfs.hpp"
#include "node.hpp"
#include "variant.hpp"
#ifndef WIN32
#include <stdint.h>
#else
#include "wstdint.h"
#endif

class FatNode: public Node
{
private:
  class Fatfs*	fs;
  uint64_t	lfnmetaoffset;
  uint64_t	dosmetaoffset;
  uint32_t	cluster;

  void		dosToVtime(vtime* vt, uint16_t dos_time, uint16_t dos_date);
  uint8_t	*readDosEntry();
public:
  FatNode(std::string name, uint64_t size, Node* parent, class Fatfs* fs);
  ~FatNode();
  void				setLfnMetaOffset(uint64_t lfnmetaoffset);
  void				setDosMetaOffset(uint64_t dosmetaoffset);
  void				setCluster(uint32_t cluster);
  virtual void			fileMapping(FileMapping* fm);
  virtual void                  extendedAttributes(Attributes* attr);
  virtual void                  modifiedTime(vtime* mt);
  virtual void                  accessedTime(vtime* at);
  virtual void                  createdTime(vtime* ct);
};

#endif