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
 *  Romain Bertholon <rbe@digital-forensic.org>
 */

#ifndef __TWOTHREETREE_HPP__
#define __TWOTHREETREE_HPP__
#include "type.hpp"
#ifndef WIN32
#include <stdint.h>
#else
#include "wstdint.h"
#endif
#include <stddef.h>
#include <string>
#include <vector>
#include "TwoThreeNode.hpp"

class TwoThreeTree
{

public:
  EXPORT	TwoThreeTree();
  EXPORT	~TwoThreeTree();

  EXPORT	uint32_t		size();
  EXPORT	bool			insert(uint32_t val);
  EXPORT	TwoThreeNode *	find(uint32_t val);
  EXPORT	bool			remove(uint32_t val);
  EXPORT	void			dump();
  EXPORT	void			clear();
  EXPORT	bool			empty();

private:
  TwoThreeNode *	__root;
  uint32_t		__size;
  std::vector<uint32_t>	__res;

  TwoThreeNode*	search(TwoThreeNode* node, uint32_t val);
  TwoThreeNode*	add(TwoThreeNode* node, uint32_t val);
  TwoThreeNode*	split(TwoThreeNode* node, uint32_t val,
		      TwoThreeNode * tr = NULL, TwoThreeNode * tl = NULL,
		      TwoThreeNode * l = NULL, TwoThreeNode * r = NULL);
  void		printNode(TwoThreeNode* node);
  void		lets_roll(TwoThreeNode *, TwoThreeNode *, TwoThreeNode *,
			  TwoThreeNode *, TwoThreeNode *, TwoThreeNode *,
			  TwoThreeNode *);
  void		clear(TwoThreeNode * node);
  void		dump(TwoThreeNode * node);
  TwoThreeNode* swap(TwoThreeNode * node, uint32_t val);
  bool		remove(TwoThreeNode * node, uint32_t val);
  void		redistribute(TwoThreeNode * node, TwoThreeNode * parent);
  void		merge(TwoThreeNode * node, TwoThreeNode * parent);
};

#endif
