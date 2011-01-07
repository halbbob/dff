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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __MFSO_HPP__
#define __MFSO_HPP__

#include <iostream>
#include <stdio.h>
#include <list>
#include <map>
#include <vector>
#include "vfs.hpp"
#ifndef WIN32
#include <stdint.h>
#else
#include "wstdint.h"
#endif
#include <string.h>
#include "node.hpp"
#include "results.hpp"
#include "vfile.hpp"
#include "DEventHandler.hpp"

class fso
{
private:
  std::list<Node *>		__update_queue;
public:
  results*			res;
  std::string			stateinfo;
  std::string			name;

  EXPORT fso(std::string name);
  EXPORT virtual ~fso();
  EXPORT virtual void		start(argument* args) = 0;
  EXPORT virtual int32_t 	vopen(class Node *n) = 0;
  EXPORT virtual int32_t 	vread(int32_t fd, void *rbuff, uint32_t size) = 0;
  EXPORT virtual int32_t 	vwrite(int32_t fd, void *wbuff, uint32_t size) = 0;
  EXPORT virtual int32_t 	vclose(int32_t fd) = 0;
  EXPORT virtual uint64_t	vseek(int32_t fd, uint64_t offset, int32_t whence) = 0;
  EXPORT virtual uint32_t	status(void) = 0;
  EXPORT virtual uint64_t	vtell(int32_t fd) = 0;
  EXPORT virtual void		setVerbose(bool verbose){}
  EXPORT virtual bool		verbose() { return false; }
  EXPORT std::list<Node *>	updateQueue();
  EXPORT void			registerTree(Node* parent, Node* head);
};

//Cache manager for attributes and list of allocated blocks for files
// class Cache
// {
// public:
//   Cache();
//   ~Cache();
// };

typedef struct
{
  class FileMapping*		fm;
  Node*				node;
  uint64_t			id;
  uint64_t			offset;
}				fdinfo;

class FdManager
{
private:
  uint32_t		allocated;
  std::vector<fdinfo*>	fds;
public:
  EXPORT FdManager();
  EXPORT ~FdManager();
  EXPORT fdinfo*	get(int32_t fd);
  EXPORT void		remove(int32_t fd);
  EXPORT int32_t	push(fdinfo* fi);
};


//Provide algorithm for certain kind of reader:
// - compression
// - crypto
// - ...
class mfso: public fso
{
private:
  std::map<Node*, class VFile*>			__origins;
  FdManager*					__fdmanager;
  class VFile*					__vfile;
  //std::list<class Node*>			nodeList;
  //std::map<std::string, class Decoder *>	decoders;

  // list of children is used to manage a bottom-up view. It gives the ability
  // to ask children file corresponding a block
  // It also gives the ability to destroy children when "this" needs to be deleted
  std::list<class mfso*>			__children;
  // parent is used for having a up to bottom view. It gives the ability
  // to ask parent.
  // it is also useful to tell its parent that the current mfso is going to
  // be destroyed
  class mfso					*__parent;

  bool						__verbose;

  class VFile*					vfileFromNode(Node* n);
  int32_t					readFromMapping(fdinfo* fi, void* buff, uint32_t size);

protected:
  //  std::string				name;
  //class Node					*_root;
//   bool					registerDecoder(std::string name, Decoder&);
//   bool					unregisterDecoder(std::string name);
//   virtual	uint64_t		getStartOffset() = 0;
//   virtual	uint64_t		getEndOffset() = 0;
//  EXPORT class Node			*createNode(class Node *parent, Decoder *decoder, uint64_t offset);
  
public:
  ///  EXPORT mfso();
  EXPORT mfso(std::string name);
  EXPORT virtual ~mfso();
  EXPORT virtual void		start(argument* args) = 0;
  EXPORT virtual int32_t 	vopen(class Node *n);
  EXPORT virtual int32_t 	vread(int32_t fd, void *buff, uint32_t size);
  EXPORT virtual int32_t 	vwrite(int32_t fd, void *buff, uint32_t size);
  EXPORT virtual int32_t 	vclose(int32_t fd);
  EXPORT virtual uint64_t	vseek(int32_t fd, uint64_t offset, int32_t whence);
  EXPORT virtual uint32_t	status(void);
  EXPORT virtual uint64_t	vtell(int32_t fd);


  EXPORT virtual void		setVerbose(bool verbose);
  EXPORT virtual bool		verbose();
  // EXPORT virtual void	pause();
  // EXPORT virtual void	resume();
  // EXPORT virtual void	kill();
  
//   bool			isBusy();

//   std::map<std::string, Decoder *>	getAvailableDecoders();

//   Node					*allocateNode(Node *parent);
};

#endif
