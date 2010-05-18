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
#include <iostream>
#include <sys/types.h>
//#include "type.hpp"
//#include "attrib.hpp"
#include "export.hpp"
#include "vfile.hpp"
#include "mfso.hpp"
#include "decoder.hpp"
#include "variant.hpp"

class Node
{
private:
  uint64_t			offset;

  class mfso*			mfsobj;
  class fso*			fsobj;
  class Metadata*		meta;

  std::string			name;

  class Node*			parent;
  std::list<class Node *>	children;
  uint32_t			childCount;
  //attrib*			attr;
  //unsigned int		same;
  //bool			is_file;
  //bool			is_root;

public:
  EXPORT Node(std::string name, class Node* parent = NULL, uint64_t offset = 0, Metadata* meta=NULL);
  EXPORT ~Node();
  EXPORT class Attributes*	getAttributes();
  EXPORT std::string		getName();
  EXPORT std::string		getPath();
  EXPORT Node*			getParent();
  EXPORT uint32_t		getChildCount();
  EXPORT std::list<class Node*>	getChildren();
  EXPORT uint64_t		getOffset();
  EXPORT void			setFsobj(mfso* obj);
  EXPORT bool			setParent(Node* parent);
  EXPORT bool			setDecoder(Metadata* decoder);
  //EXPORT string		absolute(void);
  EXPORT bool			hasChildren();
  EXPORT bool			addChild(class Node* child);
  //EXPORT bool           empty_child();
  EXPORT class VFile*		open(void);
};

#endif
