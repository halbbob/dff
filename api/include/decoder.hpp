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

#ifndef __DECODER_HPP__
#define __DECODER_HPP__

class Decoder
{
public:
  virtual bool			isRelevant(Node *n) = 0;

  std::string			getName();
  Decoder::Type			getType();
  unsigned char			*getMagic();

  Variant*			getValue(std::string key);
  Variant*			getItems();
  std::list<std::string>	getKeys();
};


class FsMetadata
{
public:
  virtual uint64_t		getBlockCount() = 0;
  map<string, DVariant*>	getBase();
  virtual bool			isDir() = 0;
  virtual bool			isFile() = 0;
  virtual bool			isLink() = 0;
  virtual map<string, vtime*>	getMACTimes() = 0;
  virtual vtime*		getModifiedTime() = 0;
  virtual vtime*		getAccessedTime() = 0;
  virtual vtime*		getCreatedTime() = 0;
  virtual string*		getOwners();
  virtual DVariant		getUid();
  virtual DVariant		getGid() = 0;
  virtual DVariant		getPermissions() = 0;
  virtual bool			isReadable(string who) = 0;
  virtual bool			isWritable(string who) = 0;
  virtual bool			isExecutable(string who) = 0;
};

#endif
