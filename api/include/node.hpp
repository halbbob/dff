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
  uint64_t              current;
  std::vector<chunck *> chuncks;
  uint64_t		size;
public:
  FileMapping();
  ~FileMapping();
  uint64_t		getSize();
  uint64_t		getChunckCount();
  chunck*               getNextChunck();
  chunck*               getPrevChunck();
  chunck*		getFirstChunck();
  chunck*		getLastChunck();
  chunck*		getChunck(uint64_t pos);
  chunck*		getChunckFromOffset(uint64_t offset);
  std::vector<chunck *> getChuncks();
  void			push(uint64_t offset, uint64_t size, class Node* origin, uint64_t originoffset);
};


class Attributes
{
private:
  std::map<std::string, class Variant*> *attrs;
public:
  Attributes();
  ~Attributes();
  void                                  push(std::string key, class Variant *value);
  std::list<std::string>                getKeys();
  Variant*                              getValue(std::string key);
  std::map<std::string, class Variant*> *get();   
};


class Node
{
private:
  //internal node id, use by cache for file mapping ?
  uint64_t                      id;
  //uint64_t                    offset;

  //class fso*                  fsobj;
  //class Metadata*             meta;

  //XXX parent could be a list of Node. Ex: Raid reconstruction based on two nodes which
  //    are aggregated to only one Node
  std::list<class Node *>       children;
  uint32_t                      childCount;

  std::string			name;
  uint64_t			size;
  class Node*                   parent;
  class mfso*			mfsobj;
  //attrib*                     attr;
  //unsigned int                same;
  //bool                        is_file;
  //bool                        is_root;

public:
  //EXPORT Node(std::string name, class Node* parent = NULL, uint64_t offset = 0, Metadata* meta=NULL);
  EXPORT Node(std::string name, uint64_t size=0, Node* parent=NULL, mfso* fsobj=NULL);
  EXPORT virtual ~Node();

  EXPORT virtual FileMapping*   getFileMapping();
  // May become the following method in case of lots of small chunck !!!
  // ability to provide a defined range
  //EXPORT virtual FileMapping*   getFileMapping(uint64_t offset=0, uint64_t range=0);
  EXPORT virtual Attributes*    getAttributes();
  EXPORT virtual uint64_t	getSize();
  EXPORT void			setSize(uint64_t size);
  //EXPORT virtual FileMapping* getSlackSpace();
  EXPORT std::string            getName();
  EXPORT std::string            getPath();
  //EXPORT vtime*			getTimes();
//   EXPORT virtual vtime*		getModifiedTime();
//   EXPORT virtual vtime*		getAccessedTime();
//   EXPORT virtual vtime*		getCreatedTime();
//   EXPORT virtual vtime*		getDeletedTime();

  EXPORT Node*                  getParent();
  EXPORT uint32_t               getChildCount();
  EXPORT std::list<class Node*> getChildren();
  // EXPORT uint64_t               getOffset();
  EXPORT void                   setFsobj(mfso* obj);
  EXPORT bool                   setParent(Node* parent);
  //EXPORT bool                 setDecoder(Metadata* decoder);
  //EXPORT string               absolute(void);
  EXPORT bool                   hasChildren();
  EXPORT bool                   addChild(class Node* child);
  //EXPORT bool                 empty_child();
  EXPORT class VFile*           open(void);
};

#endif
