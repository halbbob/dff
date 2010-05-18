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

class lfnEntry: public Metadata
{
public:
  lfnEntry();
  ~lfnEntry();
  virtual class FileMapping*	getFileMapping(class Node* node);
  virtual class Attributes*	getAttributes(class Node* node);
};

#endif
