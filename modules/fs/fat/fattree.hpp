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

#ifndef	__FATTREE_HPP__
#define __FATTREE_HPP__

#include "fatfs.hpp"
#include "node.hpp"
#include "fatnodes.hpp"
#include "vfile.hpp"
#include "entries.hpp"

// 		      if ((entry[0] != '.') && (memcmp(entry, "\0\0\0\0\0\0\0\0", 8) != 0))
// 			{
// 			  this->ectx->pushDosEntry(entry);
// 			  dos = this->converter->entryToDos(entry);
// 			  uint32_t next = dos->clustlow;
// 			  next |= (dos->clusthigh << 16);
// 			  curnode = new Node(std::string(shortname((char*)dos->name, (char*)dos->ext)), dos->size, parent, this->fs);
// 			  delete dos;
// 			  curnode->setDir();
//  			  if (entry[0] == 0xe5)
// 			    curnode->setDeleted();
// 			  this->depth += 1;
// 			  this->walk(next, curnode);
// 			  this->depth -= 1;
// 			}
// 		      //this->ctx->process();
// 		    }
// 		  else
// 		    {
// 		      if (memcmp(entry, "\0\0\0\0\0\0\0\0", 8) != 0)
// 			{
// 			  dos = this->converter->entryToDos(entry);
// 			  curnode = new Node(std::string(shortname((char*)dos->name, (char*)dos->ext)), dos->size, parent, this->fs);
// 			  curnode->setFile();
//  			  if (entry[0] == 0xe5)
// 			    curnode->setDeleted();
// 			  delete dos;
// 			}
// 		    }
// 		}
// 	    }
// 	}

class FatTree
{
private:
  Node*			origin;
  VFile*		vfile;
  class Fatfs*		fs;
  std::list<uint32_t>	recursion;
  uint32_t		depth;
  Node*			allocNode(ctx* c, Node* parent);
  void			walk_free(Node* parent);
  void			walk(uint32_t cluster, Node* parent);
  void			rootdir(Node* parent);
  bool			recurse(uint32_t cluster);

public:
  EntriesManager*		emanager;

  FatTree();
  ~FatTree();
  void	process(Node* origin, class Fatfs* fs, Node* parent);
};

#endif
