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

#ifndef __NODE_HPP__
#define __NODE_HPP__

#include <string>
#include <map>
#include <vector>
#include <set>
#include <iostream>
#include <sys/types.h>
#include "export.hpp"
#include "vfile.hpp"
#include "mfso.hpp"
#include "variant.hpp"
#include "vtime.hpp"
#include "exceptions.hpp"

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
  FileMapping();
  ~FileMapping();
  uint64_t		mappedFileSize();
  uint32_t		chunckCount();
  chunck*		firstChunck();
  chunck*		lastChunck();
  chunck*		chunckFromIdx(uint32_t idx);
  chunck*		chunckFromOffset(uint64_t offset);
  uint32_t		chunckIdxFromOffset(uint64_t offset, uint32_t begidx=0);
  std::vector<chunck *>	chuncksFromOffsetRange(uint64_t begoffset, uint64_t endoffset);
  std::vector<chunck *>	chuncksFromIdxRange(uint32_t begidx, uint32_t endidx);
  std::vector<chunck *>	chuncks();
  void			push(uint64_t offset, uint64_t size, class Node* origin=NULL, uint64_t originoffset=0);
};


class Attributes
{
private:
  std::map<std::string, class Variant*> __attrs;
public:
  Attributes();
  ~Attributes();
  void                                  push(std::string key, class Variant *value);
  std::list<std::string>                keys();
  Variant*                              value(std::string key);
  std::map<std::string, class Variant*> attributes();   
};

#define ISFILE		0x01
#define ISDIR		0x02
#define ISLINK		0x04
#define ISDELETED	0x08

class Node
{
private:
  //uint64_t                    offset;

  //XXX parent could be a list of Node. 
  //    Ex: Raid reconstruction based on two nodes which
  //    are aggregated to only one Node
  class Node*			__parent;

  std::vector<class Node *>	__children;
  uint32_t			__childcount;

  std::string			__name;
  uint64_t			__size;
  class mfso*			__mfsobj;
  uint64_t			__common_attributes;

protected:
  EXPORT void				setFile();
  EXPORT void				setDir();
  EXPORT void				setLink();
  EXPORT void				setDeleted();
  EXPORT void				setSize(uint64_t size);
  EXPORT void				setFsobj(mfso* obj);
  EXPORT void				setParent(Node* parent);

public:
  EXPORT Node(std::string name, uint64_t size=0, Node* parent=NULL, mfso* fsobj=NULL);
  EXPORT virtual ~Node();

  EXPORT virtual FileMapping*		fileMapping();
  EXPORT virtual Attributes*		attributes();

  EXPORT virtual vtime*			modifiedTime();
  EXPORT virtual vtime*			accessedTime();
  EXPORT virtual vtime*			createdTime();
  EXPORT virtual vtime*			changedTime();
  EXPORT std::map<std::string, vtime*>	times();


  EXPORT uint64_t			size();

  EXPORT std::string			path();
  EXPORT std::string			name();
  EXPORT std::string			absolute();

  EXPORT bool				isFile();
  EXPORT bool				isDir();
  EXPORT bool				isLink();
  EXPORT bool				isVDir();
  EXPORT bool				isDeleted();

  EXPORT class mfso*			fsobj();

  EXPORT Node*				parent();

  EXPORT std::vector<class Node*>	children();
  EXPORT bool				addChild(class Node* child);
  EXPORT bool				hasChildren();
  EXPORT uint32_t			childCount();

  EXPORT class VFile*			open();
};

#endif
