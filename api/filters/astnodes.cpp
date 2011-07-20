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
 *  Frederic B. <fba@digital-forensic.org>
 */

#include "astnodes.hpp"

Logical::Logical(AstNode* left, int op, AstNode* right)
{
  this->__left = left;
  this->__op = op;
  this->__right = right;
}

Logical::~Logical()
{
}

uint32_t	Logical::cost() 
{
  return 0;
}

bool		Logical::evaluate(Node* node) throw (std::string)
{
  return true; 
}

bool		Logical::evaluate(Node* node, int depth) throw (std::string)
{
  bool	ret = false;
  
  if (this->__op == OR)
    {
      if (this->__left->cost() < this->__right->cost())
	{
	  if ((ret = this->__left->evaluate(node, depth+1)) == false)
	    ret = this->__right->evaluate(node, depth+1);
	}
      else
	{
	  if ((ret = this->__right->evaluate(node, depth+1)) == false)
	    ret = this->__left->evaluate(node, depth+1);
	}
    }
  else if (this->__op == AND)
    {
      if (this->__left->evaluate(node, depth+1) && this->__right->evaluate(node, depth+1))
	ret = true;
      else
	ret = false;
    }
  else
    std::cout << "bad operator" << std::endl;//throw std::string("operator not managed");
  return ret;
}


SizeCmp::~SizeCmp()
{
}

SizeCmp::SizeCmp(CmpOperator::Op cmp, uint64_t size)
{
  this->__cmp = cmp;
  this->__size = size;
  this->__lsize = NULL;
  this->__etype = SIMPLE;
}

SizeCmp::SizeCmp(CmpOperator::Op cmp, std::vector<uint64_t>* lsize)
{
  this->__cmp = cmp;
  this->__lsize = lsize;
  this->__size = (uint64_t)-1;
  this->__etype = LIST;
}

bool		SizeCmp::__levaluate(Node* node)
{
  bool	found;
  std::vector<uint64_t>::iterator	it;

  if (this->__lsize == NULL)
    return false;
  //std::cout << std::string(3, ' ') << node->size() << std::endl;
  found = false;
  it = this->__lsize->begin();
  while ((it != this->__lsize->end()) && !found)
    {
      //std::cout << std::string(6, ' ') << *it << std::endl;
      if (node->size() == *it)
	found = true;
      it++;
    }
  if (this->__cmp == CmpOperator::EQ)
    return found == true;
  else if (this->__cmp == CmpOperator::NEQ)
    return found == false;
  else
    return false; //XXX throw bad op for in [] eval
}

bool		SizeCmp::__sevaluate(Node* node)
{
  std::string	out;

  if (this->__size == (uint64_t)-1)
    return false; //XXXX throw size not setted
  if (this->__cmp == CmpOperator::EQ)
    {
      if (node->size() == this->__size)
	{
	  //std::cout << std::string(3, ' ') << "SizeCmp::__sevaluate : " << node->size() << " == " << this->__size << " --> true " << std::endl;
	  return true;
	}
      else
	{
	  //std::cout << std::string(3, ' ') << "SizeCmp::__sevaluate : " << node->size() << " == " << this->__size << " --> false " << std::endl;
	  return false;
	}
    }
  else if (this->__cmp == CmpOperator::NEQ)
    {
      if (node->size() != this->__size)
	{
	  //std::cout << std::string(3, ' ') << "SizeCmp::__sevaluate : " << node->size() << " != " << this->__size << " --> true " << std::endl;
	  return true;
	}
      else
	{
	  //std::cout << std::string(3, ' ') << "SizeCmp::__sevaluate : " << node->size() << " != " << this->__size << " --> false " << std::endl;
	  return false;
	}
    }
  else if (this->__cmp == CmpOperator::LT)
    {
      if (node->size() < this->__size)
	{
	  //std::cout << std::string(3, ' ') << "SizeCmp::__sevaluate : " << node->size() << " < " << this->__size << " --> true " << std::endl;
	  return true;
	}
      else
	{
	  //std::cout << std::string(3, ' ') << "SizeCmp::__sevaluate : " << node->size() << " < " << this->__size << " --> false " << std::endl;
	  return false;
	}
    }
  else if (this->__cmp == CmpOperator::LTE)
    {
      if (node->size() <= this->__size)
	{
	  //std::cout << std::string(3, ' ') << "SizeCmp::__sevaluate : " << node->size() << " <= " << this->__size << " --> true " << std::endl;
	  return true;
	}
      else
	{
	  //std::cout << std::string(3, ' ') << "SizeCmp::__sevaluate : " << node->size() << " <= " << this->__size << " --> false " << std::endl;
	  return false;
	}
    }
  else if (this->__cmp == CmpOperator::GT)
    {
      if (node->size() > this->__size)
	{
	  //std::cout << std::string(3, ' ') << "SizeCmp::__sevaluate : " << node->size() << " > " << this->__size << " --> true " << std::endl;
	  return true;
	}
      else
	{
	  //std::cout << std::string(3, ' ') << "SizeCmp::__sevaluate : " << node->size() << " > " << this->__size << " --> false " << std::endl;
	  return false;
	}
    }
  else if (this->__cmp == CmpOperator::GTE)
    {
      if (node->size() >= this->__size)
	{
	  //std::cout << std::string(3, ' ') << "SizeCmp::__sevaluate : " << node->size() << " >= " << this->__size << " --> true " << std::endl;
	  return true;
	}
      else
	{
	  //std::cout << std::string(3, ' ') << "SizeCmp::__sevaluate : " << node->size() << " >= " << this->__size << " --> false " << std::endl;
	  return false;
	}
    }
}


bool		SizeCmp::evaluate(Node* node) throw (std::string)
{
  if (this->__etype == SIMPLE)
    return this->__sevaluate(node);
  else if (this->__etype == LIST)
    return this->__levaluate(node);
  else
    throw std::string("SizeCmp::evaluate() -> unknown eval type");
}

bool		SizeCmp::evaluate(Node* node, int depth) throw (std::string)
{
  if (this->__etype == SIMPLE)
    return this->__sevaluate(node);
  else if (this->__etype == LIST)
    return this->__levaluate(node);
  else
    throw std::string("SizeCmp::evaluate() -> unknown eval type");
}

uint32_t	SizeCmp::cost()
{
  return 0; 
}

