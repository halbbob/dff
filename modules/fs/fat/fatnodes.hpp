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
#include <stdint.h>

class FatNode: public Node
{
private:
  class Fatfs*	fs;
  uint64_t	lfnmetaoffset;
  uint64_t	dosmetaoffset;
  uint32_t	cluster;
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

class FatDir: public Node
{
public:
  FatDir(std::string name, uint64_t size, Node* parent, class Fatfs* fat, uint64_t offset, bool deleted=false);
  ~FatDir();
  virtual void                  extendedAttributes(Attributes* attr);
  virtual void                  modifiedTime(vtime* mt);
  virtual void                  accessedTime(vtime* at);
  virtual void                  createdTime(vtime* ct);
};

class FatFile: public Node
{
private:
  uint64_t      offset;
public:
  FatFile(std::string name, uint64_t size, Node* parent, class Fatfs* fat, uint64_t offset, bool deleted=false);
  ~FatFile();
  virtual void                  extendedAttributes(Attributes* attr);
  virtual void                  modifiedTime(vtime* mt);
  virtual void                  accessedTime(vtime* at);
  virtual void                  createdTime(vtime* ct);
};

class SlackFile: public Node
{
private:
  uint64_t      offset;
public:
  SlackFile(std::string name, uint64_t size, Node* parent, class Fatfs* fat, uint64_t offset, bool deleted=false);
  ~SlackFile();
};

#endif
