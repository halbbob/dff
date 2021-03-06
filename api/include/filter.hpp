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

#ifndef __FILTER_HPP__
#define __FILTER_HPP__

#include "eventhandler.hpp"
#include "node.hpp"
#include "../filters/astnodes.hpp"

class Filter : public EventHandler
{
public:
  Filter(std::string fname);
  ~Filter();
  std::string		query();
  std::string		filterName();
  virtual void		Event(event* e);
  void			setFilterName(std::string fname) throw (std::string);
  void			compile(std::string query) throw (std::string);
  void			processFolder(Node* nodeptr) throw (std::string);
  void			process(Node* nodeptr, bool recursive=true) throw (std::string);
  void			process(std::list<Node*> nodes) throw (std::string);
  void			process(std::vector<Node*> nodes) throw (std::string);
  void			process(uint64_t nodeid, bool recursive=true) throw (std::string);
  void			process(uint16_t fsoid, bool recursive=true) throw (std::string);
  //bool			match(Node* ptr); throw (std::string);
  std::vector<Node*>	matchedNodes();
  enum EventTypes
    {
      TotalNodesToProcess = 0x200,
      ProcessedNodes = 0x201,
      NodeMatched = 0x202,
      StopProcessing = 0x204,
      EndOfProcessing = 0x205,
      AstReset = 0x4242
    };
private:
  void			__process(Node* nodeptr, uint64_t* processed);
  void			__reset();
  void			__notifyNodesToProcess(uint64_t nodescount);
  void			__notifyMatch(Node* nodeptr);
  void			__notifyProgress(uint64_t processed);
  void			__notifyEndOfProcessing(uint64_t processed);
  event*		__ev;
  std::vector<Node*>	__matchednodes;
  std::string		__fname;
  uint32_t		__uid;
  std::string		__query;
  AstNode*		__root;
  bool			__stop;
};

#endif
