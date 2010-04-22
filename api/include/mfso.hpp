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

#ifndef __MFSO_HPP__
#define __MFSO_HPP__

#include "decoder.hpp"
#include "node.hpp"

//Cache manager for attributes and list of allocated blocks for files
class Cache
{
public:
  Cache();
  ~Cache();
};


class FdManager
{
public:
  FdManager();
  ~FdManager();
};


class mfso
{
private:
  VFile					*vfile;
  std::list<Node*>			nl;
  std::map<std::string, Decoder *>	decoders;

  // list of children is used to manage a bottom-up view. It gives the ability
  // to ask children file corresponding a block
  // It also gives the ability to destroy children when "this" needs to be deleted
  std::list<class mfso*>		*children;

  // parent is used for having a up to bottom view. It gives the ability
  // to ask parent.
  // it is also useful to tell its parent that the current mfso is going to
  // be destroyed
  class mfso				*parent;

  //fdmanager

protected:
  bool					registerDecoder(std::string name, Decoder&);
  bool					unregisterDecoder(std::string name);

public:
  EXPORT mfso();
  EXPORT virtual ~mfso();

  virtual void				start(argument* args) = 0;
  virtual list<uint64_t>		getFileBlocks() = 0;
  virtual uint64_t			getNextBlock() = 0;
  virtual uint64_t			getBlockSize() = 0;
  virtual bool				isRelevant() = 0;

  bool		isBusy();
  unsigned int	status(void);

  std::map<std::string, Decoder *>	getAvailableDecoders();

  virtual	uint64_t		getStartOffset() = 0;
  virtual	uint64_t		getEndOffset() = 0;

  EXPORT	int			vopen();
  EXPORT	int			vread();
  EXPORT	uint64_t		vseek();
  EXPORT	int			vclose();
  EXPORT	int			vwrite();
  Node					*allocateNode(Node *parent);
}

#endif
