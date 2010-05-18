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

#ifndef __LFNENTRY_HPP__
#define __LFNENTRY_HPP__

#include "node.hpp"
#include "vfile.hpp"
#include "decoder.hpp"

typedef struct 
{
  uint8_t	seq;
  uint8_t	part1[10];
  uint8_t	attributes;
  uint8_t	reserved1;
  uint8_t	chksum;
  uint8_t	part2[12];
  uint8_t	reserved2[2];
  uint8_t	part3[4];
}		lfnentry;

class LongFileName
{
public:
  LongFileName();
  ~LongFileName();
};


typedef struct 
{
  uint8_t name[8];
  uint8_t ext[3];
  uint8_t attrib;
  uint8_t lowercase;
  uint8_t ctimeten;       /* create times */
  uint8_t ctime[2];
  uint8_t cdate[2];
  uint8_t adate[2];       /* access time */
  uint8_t highclust[2];
  uint8_t wtime[2];       /* last write time */
  uint8_t wdate[2];
  uint8_t startclust[2];
  uint8_t size[4];
} dosentry;

typedef struct
{
  uint8_t	name[8];
  uint8_t	ext[3];
  uint8_t	attrib;
  uint8_t	lowercase;
  uint8_t	ctimeten;       /* create times */
  uint16_t	ctime;
  uint16_t	cdate;
  uint16_t	adate;       /* access time */
  uint16_t	highclust;
  uint16_t	wtime;       /* last write time */
  uint16_t	wdate;
  uint16_t	startclust;
  uint32_t	size;
}		dectx;

class Dos
{
private:
  bool		sanitizeEntry(dectx* ctx);
  dectx*	createDentryCtx(Node* n);
public:
  Dos();
  ~Dos();
};

class Entry: public Dos, LongFileName
{
public:
  Entry();
  ~Entry();
};

#endif
