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

#include <stdint.h>
#include "node.hpp"
#include "results.hpp"
#include "vfile.hpp"
#include "vfs.hpp"
#include <string.h>
//Cache manager for attributes and list of allocated blocks for files
// class Cache
// {
// public:
//   Cache();
//   ~Cache();
// };


// class FdManager
// {
// public:
//   FdManager();
//   ~FdManager();
// };


// class IO
// {
//   virtual int 		vopen(Node *n) = 0;
//   virtual int 		vread(int fd, void *buff, unsigned int size) = 0;
//   virtual int 		vclose(int fd) = 0;
//   virtual dff_ui64 	vseek(int fd, dff_ui64 offset, int whence) = 0;
//   virtual int 		vwrite(int fd, void *buff, unsigned int size) { return 0; } = 0;
//   virtual unsigned int	status(void) = 0;
//   virtual void		start(argument* ar);
// };

typedef struct
{
  class FileMapping*		fm;
  Node*				node;
  uint64_t			offset;
}				fdinfo;

class FdManager
{
private:
  uint32_t		allocated;
  std::vector<fdinfo*>	fds;
public:
  FdManager();
  ~FdManager();
  fdinfo*	get(int32_t fd);
  void		remove(int32_t fd);
  int32_t	push(fdinfo* fi);
};


//Provide algorithm for certain kind of reader:
// - compression
// - crypto
// - ...
class mfso//: //public fso
{
private:
  std::map<Node*, class VFile*>			__origins;
  FdManager*					__fdmanager;
  std::string					__stateinfo;
  results*					__res;
  std::string					__name;
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
  class Node					*_root;
//   bool					registerDecoder(std::string name, Decoder&);
//   bool					unregisterDecoder(std::string name);
//   virtual	uint64_t		getStartOffset() = 0;
//   virtual	uint64_t		getEndOffset() = 0;
//  EXPORT class Node			*createNode(class Node *parent, Decoder *decoder, uint64_t offset);
  void					setStateInfo(std::string stateinfo);
  void					registerTree(Node* parent, Node* head);
  
public:
  //  EXPORT mfso();
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

  EXPORT void			setVerbose(bool verbose);
  EXPORT bool			verbose();
  EXPORT std::string		stateInfo();
  EXPORT results*		res();
  EXPORT std::string		name();
  // EXPORT virtual void	pause();
  // EXPORT virtual void	resume();
  // EXPORT virtual void	kill();
  
//   bool			isBusy();

//   std::map<std::string, Decoder *>	getAvailableDecoders();

//   Node					*allocateNode(Node *parent);
};

#endif
