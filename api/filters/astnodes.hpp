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

#ifndef __ASTNODES_HPP__
#define __ASTNODES_HPP__

#include <iostream>
#include <vector>
#include "node.hpp"

class Expression;

typedef std::vector<Expression*> ArgumentsList;

class AstNode
{
public:
  virtual ~AstNode() {}
  virtual bool	evaluate(Node* node, int depth) = 0;
  virtual unsigned int	cost() = 0;
};

class Expression : public AstNode
{
  
};

class Identifier : public Expression
{
private:
  std::string*	__id;
public:
  Identifier(std::string* id): __id(id) {}
  ~Identifier() {};
  virtual bool	evaluate(Node* node, int depth) 
  {
    std::cout << std::string(depth+2, ' ') << *__id << std::endl;
  }
  virtual unsigned int cost() {return 0;}
};

class Number : public Expression
{
private:
  std::string*	__num;
public:
  Number(std::string* num): __num(num) {}
  virtual bool	evaluate(Node* node, int depth) 
  {
    std::cout << std::string(depth+2, ' ') << *__num << std::endl;
  }
};

class Comparison : public Expression
{
private:
  std::string*	__attr;
  int		__cmp;
  Expression*	__val;
  Variant*	attrToVal()
  {
    return NULL;
  }
public:
  enum
    {
      EQ,
      NEQ,
      LT,
      LTE,
      GT,
      GTE
    };
  Comparison(std::string* attr, int cmp, Expression* val) :
    __attr(attr), __cmp(cmp), __val(val) {}
  ~Comparison() {}
  virtual bool	evaluate(Node* node, int depth)
  {
    Variant* v;
    
    if ((v = node->attributesByName(*__attr, ABSOLUTE_ATTR_NAME)) == NULL)
      {
	if (*__attr == "\"size\"")
	  ;
      }
    switch (__cmp)
      {
      case EQ:
	std::cout << std::string(depth+1, ' ') << *__attr << " == " << __val->evaluate(node, depth);
      case NEQ:
	std::cout << std::string(depth+1, ' ') << *__attr << " != " << __val->evaluate(node, depth);
      case LT:
	std::cout << std::string(depth+1, ' ') << *__attr << " < " << __val->evaluate(node, depth);
      case LTE:
	std::cout << std::string(depth+1, ' ') << *__attr << " <= " << __val->evaluate(node, depth);
      case GT:
	std::cout << std::string(depth+1, ' ') << *__attr << " > " << __val->evaluate(node, depth);
      case GTE:
	std::cout << std::string(depth+1, ' ') << *__attr << " >= " << __val->evaluate(node, depth);
      }
    
    return false;
  }
  virtual unsigned int cost() {return 0;}
};

class Logical : public Expression
{
private:
  Expression*	__left;
  int		__op;
  Expression*	__right;
public:
  enum
    {
      OR,
      AND
    };
  Logical(Expression* left, int op, Expression* right) :
    __left(left), __op(op), __right(right) {}
  ~Logical() {}
  virtual unsigned int   cost() {return 0;}
  virtual bool	evaluate(Node* node, int depth)
  {
    bool	ret = false;

    if (__op == OR)
      {
	if (__left->cost() < __right->cost())
	  {
	    if ((ret = __left->evaluate(node, depth+1)) == false)
	      ret = __right->evaluate(node, depth+1);
	  }
	else
	  {
	    if ((ret = __right->evaluate(node, depth+1)) == false)
	      ret = __left->evaluate(node, depth+1);
	  }
      }
    else if (__op == AND)
      {
	if (__left->evaluate(node, depth+1) && __right->evaluate(node, depth+1))
	  ret = true;
	else
	  ret = false;
      }
    else
      std::cout << "bad operator" << std::endl;//throw std::string("operator not managed");
    return ret;
  }
};

class Operation : public Expression
{
private:
  Expression*	__left;
  std::string*	__op;
  Expression*	__right;
public:
  Operation(Expression* left, std::string* op,  Expression* right) :
    __left(left), __op(op), __right(right) {}
  ~Operation() {};
  virtual bool	evaluate(Node* node, int depth)
  {
    __left->evaluate(node, depth+1); 
    std::cout << std::string(depth+2, ' ') << *__op << std::endl; 
    __right->evaluate(node, depth+1);
  }
  virtual unsigned int	cost() {return 0;}
};

class MethodCall : public Expression
{
private:
  std::string*		__name;
  ArgumentsList*	__args;
public:
  MethodCall(std::string* name, ArgumentsList* args) :
    __name(name), __args(args) {}
  ~MethodCall() {};
  virtual bool evaluate(Node* node, int depth) 
  {
    std::cout << std::string(depth+2, ' ') << "processor: " << *__name << std::endl;
    std::cout << std::string(depth+4, ' ') << "arguments: ";

    int i;

    for (i = 0; i != __args->size(); i++)
      (*__args)[i]->evaluate(node, depth+1);
  }
  virtual unsigned int	cost() {return 0;}
};

#endif
