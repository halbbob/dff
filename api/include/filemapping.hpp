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

#ifndef __FILEMAPPING_HPP__
#define __FILEMAPPING_HPP__

#ifndef WIN32
#include <stdint.h>
#else
#include "wstdint.h"
#endif

#include "export.hpp"
#include <vector>

typedef struct
{
  uint64_t      offset;
  uint64_t      size;
  class Node*   origin;
  uint64_t	originoffset;
}               chunck;

class FileMapping
{
private:
  std::vector<chunck *> __chuncks;
  uint64_t		__mappedFileSize;
  chunck*		__prevChunck;
  void			allocChunck(uint64_t offset, uint64_t size, class Node* origin, uint64_t originoffset);
public:
  EXPORT FileMapping();
  EXPORT ~FileMapping();
  EXPORT uint64_t		mappedFileSize();
  EXPORT uint32_t		chunckCount();
  EXPORT chunck*		firstChunck();
  EXPORT chunck*		lastChunck();
  EXPORT chunck*		chunckFromIdx(uint32_t idx);
  EXPORT chunck*		chunckFromOffset(uint64_t offset);
  EXPORT uint32_t		chunckIdxFromOffset(uint64_t offset, uint32_t begidx=0);
  EXPORT std::vector<chunck *>	chuncksFromOffsetRange(uint64_t begoffset, uint64_t endoffset);
  EXPORT std::vector<chunck *>	chuncksFromIdxRange(uint32_t begidx, uint32_t endidx);
  EXPORT std::vector<chunck *>	chuncks();
  EXPORT void			push(uint64_t offset, uint64_t size, class Node* origin=NULL, uint64_t originoffset=0);
};

#endif
