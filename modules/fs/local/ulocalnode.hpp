/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __ULOCALNODE_HPP__
#define __ULOCALNODE_HPP__

//#include "variant.hpp"
#include "local.hpp"
#include "node.hpp"

class ULocalNode: public Node
{
private:
  void				utimeToVtime(time_t* t1, vtime* vt);
  struct stat*			localStat();
public:
  enum Type
    {
      FILE,
      DIR
    };
  ULocalNode(std::string name, uint64_t size, Node* parent, fso* fsobj, uint8_t type, uint32_t id);
  ~ULocalNode();
  virtual void			extendedAttributes(Attributes* attr);
  virtual void			modifiedTime(vtime* mt);
  virtual void			accessedTime(vtime* at);
  virtual void			changedTime(vtime* ct);
};

#endif
