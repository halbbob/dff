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

#include <stdio.h>
#include <iostream>

#include "TwoThreeTree.hpp"

TwoThreeTree::TwoThreeTree()
{
  this->__root = NULL;
  this->__size = 0;
}

TwoThreeTree::~TwoThreeTree()
{
}

TwoThreeNode *	TwoThreeTree::search(TwoThreeNode * node, uint32_t val)
{
  if (node == NULL)
    return NULL;
  else if (node->isTwoNode())
    {
      if (val == node->leftVal())
	return node;
      if (val < node->leftVal())
	return this->search(node->leftChild(), val);
      else
	return this->search(node->rightChild(), val);
    }
  else
    {
      if ((val == node->leftVal()) || (val == node->rightVal()))
	return node;
      if (val < node->leftVal())
	return this->search(node->leftChild(), val);
      else if (val < node->rightVal())
	return this->search(node->middleChild(), val);
      else
	return this->search(node->rightChild(), val);
    }
}

void	TwoThreeTree::clear()
{
  clear(__root);
  __root = NULL;
}

void	TwoThreeTree::clear(TwoThreeNode * node)
{
  if (node->isLeaf())
    {
      delete node;
      return ;
    }
  if (node->isTwoNode())
    {
      if (node->leftChild())
	clear(node->leftChild());
      if (node->rightChild())
	clear(node->rightChild());
    }
  else
    {
      if (node->leftChild())
	clear(node->leftChild());
      if (node->middleChild())
	clear(node->middleChild());
      if (node->rightChild())
	clear(node->rightChild());
    }
  delete node;
}

TwoThreeNode *		TwoThreeTree::add(TwoThreeNode* node, uint32_t val)
{
  if (!node)
    return NULL;
  if (node->isLeaf())
    {
      if (node->isTwoNode())
	{
	  if (val < node->leftVal())
	    {
	      uint32_t	tmp = node->leftVal();
	      node->setLeftVal(val);
	      node->setRightVal(tmp);
	    }
	  else
	    node->setRightVal(val);
	  node->toThreeNode();
	}
      else
	return split(node, val);
      return NULL;
    }
  if (node->isTwoNode())
    {
      if (val > node->leftVal())
	this->add(node->rightChild(), val);
      else
	this->add(node->leftChild(), val);
      return NULL;
    }
  else
    {
      if (val < node->leftVal())
	this->add(node->leftChild(), val);
      else if (val > node->rightVal())
	this->add(node->rightChild(), val);
      else
	this->add(node->middleChild(), val);
    }
  return NULL;
}

TwoThreeNode *	TwoThreeTree::split(TwoThreeNode * node, uint32_t val,
				    TwoThreeNode * tl, TwoThreeNode * tr,
				    TwoThreeNode * tl2, TwoThreeNode * tr2)
{
  TwoThreeNode *	r;
  TwoThreeNode *	l;
  TwoThreeNode *	tmp_l = tl;
  TwoThreeNode *	tmp_r = tr;
  TwoThreeNode *	j = NULL;
  TwoThreeNode *	parent;
  uint32_t		min;
  uint32_t		mid;
  uint32_t		max;

  if (val < node->leftVal())
    {
      min = val;
      mid = node->leftVal();
      max = node->rightVal();
    }
  else if (val < node->rightVal())
    {
      min = node->leftVal();
      mid = val;
      max = node->rightVal();
    }
  else
    {
      min = node->leftVal();
      mid = node->rightVal();
      max = val;
    }
  l = new TwoThreeNode(min, NULL);
  r = new TwoThreeNode(max, NULL);
  if (node == __root)
    {
      j = new TwoThreeNode(mid, NULL);
      this->__root = j;
      parent = j;
      if (node->isLeaf())
	{
	  parent->setLeftChild(l);
	  parent->setRightChild(r);
	  delete node;
	  return NULL;
	}
      parent->setLeftChild(l);
      parent->setRightChild(r);
    }
  else
    parent = node->parent();

  uint16_t	tt = 4;
  if (parent->leftChild() == node)
    tt = 0;
  else if (parent->rightChild() == node)
    tt = 1;
  else if (parent->middleChild() == node)
    tt = 2;
  if (!node->isLeaf())
    lets_roll(l, r, tl, tr, tl2, tr2, parent);
  if (!j && parent->isTwoNode())
    {
      parent->toThreeNode(mid);
      if (node == parent->leftChild())
	{
	  parent->setLeftChild(l);
	  parent->setMiddleChild(r);
	}
      else
	{
	  parent->setMiddleChild(l);
	  parent->setRightChild(r);
	}
    }
  else if (!j)
    {
      if (tt == 0)
	{
	  tmp_l = parent->middleChild();
	  tmp_r = parent->rightChild();
	  split(parent, mid, l, r, tmp_l, tmp_r);
	}
      else if (tt == 1)
	{
	  tmp_l = parent->leftChild();
	  tmp_r = parent->middleChild();
	  split(parent, mid, tmp_l, tmp_r, l, r);
	}
      else if (tt == 2)
	{
	  tmp_l = parent->leftChild();
	  tmp_r = parent->rightChild();
	  split(parent, mid, tmp_l, l, r, tmp_r);
	}
    }
  delete node;
  return NULL;
}

bool		TwoThreeTree::insert(uint32_t val)
{
  TwoThreeNode *	node;

  if (this->__root == NULL)
    this->__root = new TwoThreeNode(val, NULL);
  else
    {
      try
	{
	  if ((node = this->add(this->__root, val)) != NULL)
	    this->__root = node;
	}
      catch (...)
	{
	  std::cerr << "TwoThreeTree::insert() : "
	    "Unknown exception while inserting " << val << "." << std::endl;
	  return false;
	}
    }
  this->__size++;
  return true;
}

TwoThreeNode *	TwoThreeTree::find(uint32_t val)
{
  return this->search(this->__root, val);
}

uint32_t	TwoThreeTree::size()
{
  return __size;
}

bool	TwoThreeTree::remove(uint32_t val)
{
  TwoThreeNode *	node;
  TwoThreeNode *	leaf_node;
  bool			empty = false;

  std::cout << "removing " << val << std::endl;
  node = this->find(val);
  if (node)
    {
      __size--;
      leaf_node = swap(node, val);
      dump();
      if (!leaf_node)
	{
	  std::cout << "done NULL " << val << std::endl;
	  return leaf_node;
	}
      if (leaf_node->leftVal() == val)
	{
	  leaf_node->setLeftVal(0);
	  if (leaf_node->isTwoNode())
	    empty = true;
	  else
	    {
	      leaf_node->setLeftVal(leaf_node->rightVal());
	      leaf_node->setNodeType(TWO_NODE);
	    }
	}
      else
	{
	  leaf_node->setRightVal(0);
	  leaf_node->setNodeType(TWO_NODE);
	  redistribute(leaf_node, leaf_node->parent());
	  
	  TwoThreeNode * parent = leaf_node->parent();
	  if (parent && !parent->leftVal() && !parent->rightVal())
	    remove(parent, val);
	  // merge(parent, parent->parent());
	  // empty = true;
	}
      if (empty)
	{
	  if (leaf_node == __root)
	    {
	      delete __root;
	      __root = node;
	      std::cout << "done root" << val << std::endl;
	      return true;
	    }
	  else
	    {
	      bool	b = remove(leaf_node, val);
	      std::cout << "done " << val << std::endl;
	      return b;
	    }
	}
    }
  else
    {
      std::cout << "done false" << val << std::endl;
      return false;
    }
  std::cout << "done end " << val << std::endl;
  return true;
}

bool	TwoThreeTree::remove(TwoThreeNode * node, uint32_t val)
{
  TwoThreeNode *	parent = node->parent();

  if (!parent)
    return false;
  if (
      ((parent->leftChild() != node) && !parent->leftChild()->isTwoNode())
      || (!parent->isTwoNode() && (parent->middleChild() != node)
	  && !parent->middleChild()->isTwoNode())
      || ((parent->rightChild() != node)
	  && !parent->rightChild()->isTwoNode()))
    redistribute(node, parent);
  else
    {
      std::cout << "merging" << std::endl;
      merge(node, parent);
      dump();

      if (!parent->rightVal() && !parent->leftVal())
	{
	  std::cout << "removing" << std::endl;
	  remove(parent, val);

	  if (parent == __root)
	    {
	      std::cout << "parent is root" << std::endl;
	      __root = __root->leftChild();
	      
	      //delete parent->leftChild();
	      delete parent;
	    }

	}
    }
  return true;
}

TwoThreeNode *	TwoThreeTree::swap(TwoThreeNode * node, uint32_t val)
{
  uint32_t		tmp;
  TwoThreeNode *	node_bak = node;

  while  (!node->isLeaf()) // if we are not in a leaf, we swap
    {
      if (node->isTwoNode())
	{
	  if (val >= node->leftVal())
	    node = node->rightChild();
	  else
	    node = node->leftChild();
	}
      else // if the node is a 3 nodes
	{	  
	  if (node_bak->leftVal() == val) // if it is the leftVal of node
	    {
	      if (val < node->leftChild()->leftVal())
		node = node->leftChild();
	      else
		node = node->middleChild();
	    }
	  else
	    node = node->rightChild();
	}
    }
  if (node_bak->isTwoNode())
    {      
      tmp = node->leftVal();
      node->setLeftVal(node->leftVal());
      node_bak->setLeftVal(tmp);
    }
  else
    {
      if (node_bak->leftVal() == val)
	{
	  tmp = node_bak->leftVal();
	  node_bak->setLeftVal(node->leftVal());
	  node->setLeftVal(val);
	}
      else
	{
	  tmp = node_bak->rightVal();
	  node_bak->setRightVal(node->leftVal());
	  node->setLeftVal(val);
	}
    }

  if (node->isTwoNode())
    return node;
  node->setNodeType(TWO_NODE);
  //  if (node->leftVal() == val)
  node->setLeftVal(node->rightVal());
  node->setRightVal(0);
  return NULL;
}

void	TwoThreeTree::lets_roll(TwoThreeNode * l, TwoThreeNode * r,
				TwoThreeNode * tl, TwoThreeNode * tr,
				TwoThreeNode * tl2, TwoThreeNode * tr2,
				TwoThreeNode * parent)
{
  if (!parent->isTwoNode())
    {
      l->setLeftChild(tl);
      l->setRightChild(tr);
      r->setLeftChild(tl2);
      r->setRightChild(tr2);
      if (r->leftVal() > l->leftVal())
	;
	//	parent->setRightChild(r);
      else
	{
	  parent->setMiddleChild(r);
	  //	  parent->setRightChild(l); 
	}
    }
  else
    {
      l->setLeftChild(tl);
      l->setRightChild(tr);
      
      if (l->leftVal() > r->leftVal())
	{
	  parent->setMiddleChild(l);
	  parent->setRightChild(r);
	}
      else
	parent->setMiddleChild(r);
      r->setLeftChild(tl2);
      r->setRightChild(tr2);

    }
}

void	TwoThreeTree::redistribute(TwoThreeNode * node, TwoThreeNode * parent)
{
  if (parent->isTwoNode())
    {
      if (node == parent->leftChild())
	{
	  if (parent->rightChild()->isTwoNode())
	    {
	      parent->leftChild()->setLeftVal(parent->leftVal());
	      parent->leftChild()->setRightVal(parent->rightChild()->leftVal());
	      parent->setLeftVal(0);
	      parent->setRightVal(0);
	      
	      delete parent->rightChild();
	      parent->setRightChild(NULL);
		
	      std::cout << "red 2 nodes le ch" << std::endl;
	      // parent->setRightVal(parent->rightChild()->leftVal());
	      parent->leftChild()->setNodeType(THREE_NODE);
	      if (!node->isLeaf())
		{
		  std::cout << "red 2 nodes le ch" << std::endl;
		  parent->setRightChild(parent->rightChild()->rightChild());
		  parent->setMiddleChild(parent->rightChild()->leftChild());
		  parent->setLeftChild(node->leftChild());		  
		}
	    }
	  else
	    {
	      parent->leftChild()->setLeftVal(parent->leftVal());
	      parent->leftChild()->setRightChild(parent->rightChild()->leftChild());
	      parent->setLeftVal(parent->rightChild()->leftVal());
	      parent->rightChild()->setNodeType(TWO_NODE);
	      parent->rightChild()->setLeftVal(parent->rightChild()->rightVal());
	      parent->rightChild()->setRightVal(0);
	      parent->rightChild()->setLeftChild(parent->rightChild()->middleChild());
	    }
	}
      else
	{
	  if (parent->leftChild()->isTwoNode())
	    {
	      parent->setRightVal(parent->leftVal());
	      parent->setLeftVal(parent->leftChild()->leftVal());
	      parent->setNodeType(THREE_NODE);
	      parent->leftChild()->setLeftVal(parent->leftVal());
	      parent->setLeftVal(parent->rightChild()->leftVal());
	      parent->rightChild()->setLeftVal(parent->rightChild()->rightVal());
	      parent->rightChild()->setRightVal(0);
	      parent->rightChild()->setNodeType(TWO_NODE);
	    }
	  else
	    {
	      std::cout << "red 2 nodes r child" << std::endl ; // HERE IS THE BUG
	      parent->rightChild()->setLeftVal(parent->leftVal());
	      parent->setLeftVal(parent->leftChild()->rightVal());
	      parent->leftChild()->setNodeType(TWO_NODE);
	      parent->leftChild()->setRightVal(0);
	      parent->rightChild()->setRightChild(parent->rightChild()->leftChild());
	      parent->rightChild()->setLeftChild(parent->leftChild()->rightChild());
	      parent->leftChild()->setRightChild(parent->leftChild()->middleChild());
	    }
	}
      // delete node;
    }
  else
    {
      if (node == parent->leftChild())
	{
	  if (parent->middleChild()->isTwoNode())
	    {
	      node->setLeftVal(parent->leftVal());
	      node->setRightVal(parent->middleChild()->leftVal());
	      node->setNodeType(THREE_NODE);
	      parent->setLeftVal(parent->rightVal());
	      parent->setNodeType(TWO_NODE);
	      parent->setMiddleChild(NULL);
	    }
	  else
	    {
	      node->setLeftVal(parent->leftVal());
	      node->setNodeType(TWO_NODE);
	      node->setRightChild(parent->middleChild()->leftChild());
	      parent->setLeftVal(parent->middleChild()->leftVal());
	      parent->middleChild()->setLeftVal(parent->middleChild()->rightVal());
	      parent->setNodeType(TWO_NODE);
	    }
	}
      else if (node == parent->middleChild())
	{

	  if (parent->rightChild()->isTwoNode())
	    {
	      parent->setNodeType(TWO_NODE);
	      parent->leftChild()->setRightVal(parent->leftVal());
	      parent->setLeftVal(parent->rightVal());
	      parent->setRightVal(0);
	    }
	  else
	    {
	      parent->middleChild()->setLeftVal(parent->rightVal());
	      parent->middleChild()->setNodeType(TWO_NODE);
	      parent->setRightVal(parent->rightChild()->leftVal());
	      parent->rightChild()->setNodeType(TWO_NODE);
	      parent->rightChild()->setLeftVal(parent->rightChild()->rightVal());
	    }
	}
      else
	{
	  std::cout << "trewtrewt" << std::endl;
	}
    }
}

void	TwoThreeTree::merge(TwoThreeNode * node, TwoThreeNode * parent)
{
  std::cout << "merging"<< std::endl;
  if (parent->isTwoNode())
    {
      if (node == parent->rightChild())
	{
	  std::cout << "2 node right child" << std::endl;
	  parent->leftChild()->setNodeType(THREE_NODE);
   	  parent->leftChild()->setRightVal(parent->leftVal());
	  parent->leftChild()->setMiddleChild(parent->leftChild()->rightChild());
	  parent->leftChild()->setRightChild(parent->rightChild()->leftChild());
	  /* 
	     if (!parent->rightChild()->isTwoNode())
	     {
	     parent->rightChild()->setNodeType(TWO_NODE);
	     parent->rightChild()->setLeftVal(parent->rightChild()->rightVal());
	  */
	  parent->setRightVal(0);
	  //}
	  parent->setLeftVal(0);
	  delete parent->rightChild();
	  parent->setRightChild(NULL);
	}
      else // if node == parent->leftChild()
	{
	  std::cout << "2 node left child." << std::endl;
	  parent->rightChild()->setNodeType(THREE_NODE);
	  parent->rightChild()->setRightVal(parent->rightChild()->leftVal());
	  parent->rightChild()->setLeftVal(parent->leftVal());
	  parent->setLeftVal(0);
	  parent->rightChild()->setMiddleChild(parent->rightChild()->leftChild());
	  parent->rightChild()->setLeftChild(parent->leftChild()->leftChild());
	  delete parent->leftChild();
	  parent->setLeftChild(NULL);
	}
    }
  else // if node->isThreeNode()
    {
      if (node == parent->leftChild())
	{
	  std::cout << "3 node left child" << std::endl;
	  parent->leftChild()->setLeftVal(parent->leftVal());
	  parent->leftChild()->setRightVal(parent->middleChild()->leftVal());
	  parent->leftChild()->setMiddleChild(parent->middleChild()->leftChild());
	  parent->leftChild()->setNodeType(THREE_NODE);

	  parent->leftChild()->setRightChild(parent->middleChild()->rightChild());
	  parent->setLeftVal(parent->rightVal());
	  parent->setNodeType(TWO_NODE);
	  delete parent->middleChild();
	  parent->setMiddleChild(NULL);
	}
      else if (node == parent->middleChild())
	{
	  std::cout << "3 node mid  child" << std::endl;
	  parent->leftChild()->setRightVal(parent->leftVal());
	  parent->setLeftVal(parent->rightVal());
	  parent->setNodeType(TWO_NODE);
	  parent->leftChild()->setNodeType(THREE_NODE);

	  parent->leftChild()->setMiddleChild(parent->leftChild()->rightChild());
	  parent->leftChild()->setRightChild(parent->middleChild()->leftChild());
	  delete parent->middleChild();
	  parent->setMiddleChild(NULL);
	}
      else
	{
	  std::cout << "3 node right child" << std::endl;
	  parent->rightChild()->setLeftVal(parent->middleChild()->leftVal());
	  parent->rightChild()->setRightVal(parent->rightVal());
	  parent->setNodeType(TWO_NODE);
	  
	  parent->rightChild()->setRightChild(parent->rightChild()->leftChild());
	  parent->rightChild()->setMiddleChild(parent->middleChild()->rightChild());
	  parent->rightChild()->setLeftChild(parent->middleChild()->leftChild());

	  parent->rightChild()->setNodeType(THREE_NODE);
	  delete parent->middleChild();
	  parent->setMiddleChild(NULL);
	}
    }
}

bool	TwoThreeTree::empty()
{
  return ((this->__size == 0) ? true : false);
}

void	TwoThreeTree::dump()
{
  std::cout << "####### DUMP ########" << std::endl;
  dump(__root);
  std::cout << "####### END DUMP ########" << std::endl << std::endl;
}

void		TwoThreeTree::dump(TwoThreeNode * node)
{
  static int	nb_sp = 0;

  for (int i = 0; i < nb_sp; ++i)
    std::cout << " ";
  std::cout << node->leftVal();
  if (!node->isTwoNode())
    std::cout << " - " << node->rightVal();
  std::cout << std::endl;  
  if (node->isLeaf())
    return ;
  if (node->isTwoNode())
    {
      if (node->leftChild())
	{
	  std::cout << "2lchild : ";
	  nb_sp += 2;
	  dump(node->leftChild());
	  nb_sp -= 2;
	}
      if (node->rightChild())
	{
	  std::cout << "2rchild : ";
	  nb_sp += 2;
	  dump(node->rightChild());
	  nb_sp -= 2;
	}
    }
  else
    {
      if (node->leftChild())
	{
	  std::cout << "3lchild : ";
	  nb_sp += 2;
	  dump(node->leftChild());
	  nb_sp -= 2;
	}
      if (node->middleChild())
	{
	  std::cout << "3mchild : ";
	  nb_sp += 2;
	  dump(node->middleChild());
	  nb_sp -= 2;
	}
      if (node->rightChild())
	{
	  std::cout << "3rchild : ";
	  nb_sp += 2;
	  dump(node->rightChild());
	  nb_sp -= 2;
	}
    }
}

void		TwoThreeTree::printNode(TwoThreeNode* node)
{
  if (node->isTwoNode())
    {
      if (!node->isLeaf())
	printf("     %d -- %d\n\n", node->leftVal(), node->rightVal());
      else
	printf("     %d -- %d\n\n", node->leftVal(), node->rightVal());
    }
  else
    {
      if (!node->isLeaf())
	{
	  if (node->middleChild() != NULL)
	    printf("          %d -- %d\n\n", node->leftVal(),  node->rightVal());
	}
      else
	printf("      %d -- %d\n\n", node->leftVal(), node->rightVal());
    }
}
