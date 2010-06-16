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
//#include "type.hpp"
//#include "attrib.hpp"
#include "export.hpp"
#include "vfile.hpp"
#include "mfso.hpp"
#include "variant.hpp"
#include "vtime.hpp"

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
  uint32_t		chunckIdxFromOffset(uint64_t offset);
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

class Node
{
private:
  //internal node id, use by cache for file mapping ?
  uint64_t                      __id;
  //uint64_t                    offset;

  //class fso*                  fsobj;
  //class Metadata*             meta;

  //XXX parent could be a list of Node. Ex: Raid reconstruction based on two nodes which
  //    are aggregated to only one Node
  std::vector<class Node *>       __children;
  uint32_t                      __childcount;

  std::string			__name;
  uint64_t			__size;
  class Node*                   __parent;
  class mfso*			__mfsobj;
  //attrib*                     attr;
  //unsigned int                same;
  //bool                        is_file;
  //bool                        is_root;

public:
  //EXPORT Node(std::string name, class Node* parent = NULL, uint64_t offset = 0, Metadata* meta=NULL);
  EXPORT Node(std::string name, uint64_t size=0, Node* parent=NULL, mfso* fsobj=NULL);
  EXPORT virtual ~Node();

  EXPORT virtual FileMapping*   fileMapping();
  // May become the following method in case of lots of small chunck !!!
  // ability to provide a defined range
  //EXPORT virtual FileMapping*   getFileMapping(uint64_t offset=0, uint64_t range=0);
  EXPORT virtual Attributes*    attributes();
  EXPORT virtual uint64_t	size();
  EXPORT void			setSize(uint64_t size);
  //EXPORT virtual FileMapping* getSlackSpace();
  EXPORT std::string		absolute();
  EXPORT std::string            name();
  EXPORT std::string            path();
  EXPORT class mfso*		fsobj();

  //EXPORT vtime*			getTimes();
//   EXPORT virtual vtime*		getModifiedTime();
//   EXPORT virtual vtime*		getAccessedTime();
//   EXPORT virtual vtime*		getCreatedTime();
//   EXPORT virtual vtime*		getDeletedTime();

  EXPORT Node*                  parent();
  EXPORT uint32_t               childCount();
  EXPORT std::vector<class Node*> children();
  EXPORT void                   setFsobj(mfso* obj);
  EXPORT bool                   setParent(Node* parent);
  EXPORT bool                   hasChildren();
  EXPORT bool                   addChild(class Node* child);
  EXPORT class VFile*           open(void);
};

#endif
