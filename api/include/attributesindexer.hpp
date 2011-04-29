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
 *  Solal J. <sja@digital-forensic.org>
 */

#ifndef __ATTRIBUTESINDEXER_HPP__
#define __ATTRIBUTESINDEXER_HPP__

#ifndef WIN32
  #include <stdint.h>
#else
  #include "wstdint.h"
#endif

#include "eventhandler.hpp"
#include "export.hpp"
#include "exceptions.hpp"
#include "node.hpp"
#include "vfs.hpp"

#include <vector>
#include <deque>
#include <list>
#include <set>

class AttributesIndexer: public EventHandler
{
private:
  EXPORT 	        AttributesIndexer();
  EXPORT                ~AttributesIndexer();
  AttributesIndexer&    operator=(AttributesIndexer&);
  AttributesIndexer(const AttributesIndexer&);
  std::map<std::string, uint8_t>	__attrNamesAndTypes;
  EXPORT void				__mapAttrNamesAndTypes(Node* node);

public:
  EXPORT static AttributesIndexer&   Get();

  EXPORT virtual void	Event(event *e);
  EXPORT std::map<std::string, uint8_t>	attrNamesAndTypes();
};

#endif
