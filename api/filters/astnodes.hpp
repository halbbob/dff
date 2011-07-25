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
#include "search.hpp"


typedef std::vector<uint64_t>		NumberList;
typedef std::vector<std::string*>	StringList;

class Processor
{
public:
  ~Processor();
  Processor(std::string* name, std::vector<std::string*>* expr);
  std::string*			name();
  std::vector<std::string*>*	arguments();
private:
  std::string*			__name;
  std::vector<std::string* >*	__args;
};

class AstNode
{
public:
  virtual ~AstNode() {}
  virtual void		compile() throw (std::string) = 0;
  virtual bool		evaluate(Node* node, int depth) throw (std::string) = 0;
  virtual bool		evaluate(Node* node) throw (std::string) = 0;
  virtual uint32_t	cost() = 0;
};

typedef struct
{
  typedef enum
    {
      EQ,
      NEQ,
      LT,
      LTE,
      GT,
      GTE
    }	Op;
}	CmpOperator;

class Logical : public AstNode
{
private:
  AstNode*	__left;
  int		__op;
  AstNode*	__right;
public:
  enum
    {
      OR,
      AND
    };
  Logical(AstNode* left, int op, AstNode* right);
  ~Logical();
  virtual uint32_t	cost();
  virtual void		compile() throw (std::string);
  virtual bool		evaluate(Node* node) throw (std::string);
  virtual bool		evaluate(Node* node, int depth) throw (std::string);
};


class SizeCmp: public AstNode
{
public:
  ~SizeCmp();
  SizeCmp(CmpOperator::Op cmp, uint64_t size);
  SizeCmp(CmpOperator::Op cmp, std::vector<uint64_t>* lsize);
  virtual void			compile() throw (std::string);
  virtual bool			evaluate(Node* node) throw (std::string);
  virtual bool			evaluate(Node* node, int depth) throw (std::string);
  virtual uint32_t		cost();
private:
  enum EType
    {
      SIMPLE,
      LIST
    };
  EType				__etype;
  CmpOperator::Op		__cmp;
  std::vector<uint64_t>*	__lsize;
  uint64_t			__size;
  bool				__levaluate(Node* node);
  bool				__sevaluate(Node* node);
};


class MimeCmp: public AstNode
{
public:
  ~MimeCmp();
  MimeCmp(CmpOperator::Op cmp, std::string* str);
  MimeCmp(CmpOperator::Op cmp, std::vector<std::string* >* lstr);
  virtual void			compile() throw (std::string);
  virtual bool			evaluate(Node* node) throw (std::string);
  virtual bool			evaluate(Node* node, int depth) throw (std::string);
  virtual uint32_t		cost();
private:
  enum EType
    {
      SIMPLE,
      LIST
    };
  EType				__etype;
  CmpOperator::Op		__cmp;
  std::vector<std::string* >*	__lstr;
  std::string*			__str;
  std::vector<Search*>*		__lctx;
  Search*			__ctx;
  Search*			__createCtx(std::string* str);
  bool				__levaluate(Node* node);
  bool				__sevaluate(Node* node);
};


class NameCmp: public AstNode
{
public:
  ~NameCmp();
  NameCmp(CmpOperator::Op cmp, Processor* proc);
  NameCmp(CmpOperator::Op cmp, std::vector<Processor* >* lstr);
  virtual void			compile() throw (std::string);
  virtual bool			evaluate(Node* node) throw (std::string);
  virtual bool			evaluate(Node* node, int depth) throw (std::string);
  virtual uint32_t		cost();
private:
  enum EType
    {
      SIMPLE,
      LIST
    };
  EType				__etype;
  CmpOperator::Op		__cmp;
  std::vector<Processor*>*	__lproc;
  Processor*			__proc;
  std::vector<Search*>		__lctx;
  Search*			__ctx;
  Search*			__createCtx(Processor* proc);
  bool				__levaluate(Node* node);
  bool				__sevaluate(Node* node);
};


// class Identifier : public Expression
// {
// private:
//   std::string*	__id;
// public:
//   Identifier(std::string* id): __id(id) {}
//   ~Identifier() {};
//   virtual bool	evaluate(Node* node, int depth) 
//   {
//     std::cout << std::string(depth+2, ' ') << *__id << std::endl;
//   }
//   virtual unsigned int cost() {return 0;}
// };

// class Number : public Expression
// {
// private:
//   std::string*	__num;
// public:
//   Number(std::string* num): __num(num) {}
//   virtual bool	evaluate(Node* node, int depth) 
//   {
//     std::cout << std::string(depth+2, ' ') << *__num << std::endl;
//   }
// };

// class Comparison : public AstNode
// {
// private:
//   std::string*	__attr;
//   int		__cmp;
//   Expression*	__val;
//   Variant*	attrToVal()
//   {
//     return NULL;
//   }
// public:
//   enum
//     {
//       EQ,
//       NEQ,
//       LT,
//       LTE,
//       GT,
//       GTE
//     };
//   Comparison(std::string* attr, int cmp, Expression* val) :
//     __attr(attr), __cmp(cmp), __val(val) {}
//   ~Comparison() {}
//   virtual bool	evaluate(Node* node, int depth)
//   {
//     Variant* v;
    
//     if ((v = node->attributesByName(*__attr, ABSOLUTE_ATTR_NAME)) == NULL)
//       {
// 	if (*__attr == "\"size\"")
// 	  ;
//       }
//     switch (__cmp)
//       {
//       case EQ:
// 	std::cout << std::string(depth+1, ' ') << *__attr << " == " << __val->evaluate(node, depth);
//       case NEQ:
// 	std::cout << std::string(depth+1, ' ') << *__attr << " != " << __val->evaluate(node, depth);
//       case LT:
// 	std::cout << std::string(depth+1, ' ') << *__attr << " < " << __val->evaluate(node, depth);
//       case LTE:
// 	std::cout << std::string(depth+1, ' ') << *__attr << " <= " << __val->evaluate(node, depth);
//       case GT:
// 	std::cout << std::string(depth+1, ' ') << *__attr << " > " << __val->evaluate(node, depth);
//       case GTE:
// 	std::cout << std::string(depth+1, ' ') << *__attr << " >= " << __val->evaluate(node, depth);
//       }
    
//     return false;
//   }
//   virtual unsigned int cost() {return 0;}
// };

// class Operation : public Expression
// {
// private:
//   Expression*	__left;
//   std::string*	__op;
//   Expression*	__right;
// public:
//   Operation(Expression* left, std::string* op,  Expression* right) :
//     __left(left), __op(op), __right(right) {}
//   ~Operation() {};
//   virtual bool	evaluate(Node* node, int depth)
//   {
//     __left->evaluate(node, depth+1); 
//     std::cout << std::string(depth+2, ' ') << *__op << std::endl; 
//     __right->evaluate(node, depth+1);
//   }
//   virtual unsigned int	cost() {return 0;}
// };

// class MethodCall : public Expression
// {
// private:
//   std::string*		__name;
//   ArgumentsList*	__args;
// public:
//   MethodCall(std::string* name, ArgumentsList* args) :
//     __name(name), __args(args) {}
//   ~MethodCall() {};
//   virtual bool evaluate(Node* node, int depth) 
//   {
//     std::cout << std::string(depth+2, ' ') << "processor: " << *__name << std::endl;
//     std::cout << std::string(depth+4, ' ') << "arguments: ";

//     int i;

//     for (i = 0; i != __args->size(); i++)
//       (*__args)[i]->evaluate(node, depth+1);
//   }
//   virtual unsigned int	cost() {return 0;}
// };

#endif
