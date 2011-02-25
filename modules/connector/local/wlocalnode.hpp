/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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
 *  Christophe Malinge <cma@digital-forensic.org>
 */

#ifndef __WLOCALNODE_HPP__
#define __WLOCALNODE_HPP__

#include "node.hpp"

class WLocalNode: public Node
{
protected:
  std::string	basePath;
  bool			cleanPath;
  void			wtimeToVtime(FILETIME *, vtime *);
  //struct stat*	localStat();

public:
  enum Type
    {
      FILE,
      DIR
    };
  WLocalNode(std::string, uint64_t, Node *, fso *, uint8_t);
  ~WLocalNode();
  void			setBasePath(const char *);
  /*virtual void	extendedAttributes(Attributes *);
  virtual void	modifiedTime(vtime *);
  virtual void	accessedTime(vtime *);
  virtual void	createdTime(vtime *);*/
};

#endif
