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


#ifndef __CARVER_HPP__
#define __CARVER_HPP__

#include "node.hpp"
#include "common.hpp"
#include "DEventHandler.hpp"

//Let the possibility to modify the matching footer or to dynamically set the window
//representing the carved file.

class CarvedNode: public Node
{
private:
  uint64_t	__start;
  Node*		__origin;
public:
  CarvedNode(std::string name, uint64_t size, Node* parent, fso* fsobj);
  ~CarvedNode();
  void		setStart(uint64_t start);
  void		setOrigin(Node* origin);
  virtual void	fileMapping(class FileMapping* fm);
};

class Carver: public mfso, public DEventHandler
{
private:
  Node			*inode;
  Node			*root;
  VFile			*ifile;
  //FileHandler		*filehandler;
  //fdmanager		*fdm;
  BoyerMoore		*bm;
  vector<context*>	ctx;
  unsigned int		maxNeedle;
  bool			aligned;
  bool			stop;
  string		Results;

  bool			createFile();
  void			createNode(Node *parent, uint64_t start, uint64_t end);
  unsigned int		createWithoutFooter(Node *parent, vector<uint64_t> *headers, unsigned int max);
  unsigned int		createWithFooter(Node *parent, vector<uint64_t> *headers, vector<uint64_t> *footers, uint32_t max);
  int		        createTree();
  void			mapper();
  std::string		generateName(uint64_t start, uint64_t end);

public:
  Carver();
  ~Carver();
  uint64_t		tell();
  EXPORT string		process(list<description *> *d, uint64_t start, bool aligned);
  virtual void          start(argument *arg);
  virtual void		Event(DEvent *e);
  int			Read(char *buffer, unsigned int size);
};

#endif
