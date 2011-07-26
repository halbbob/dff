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
typedef std::vector<vtime*>		TimeList;

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


class TimeCmp: public AstNode
{
public:
  ~TimeCmp();
  TimeCmp(CmpOperator::Op cmp, vtime* ts);
  TimeCmp(CmpOperator::Op cmp, std::vector<vtime*>* lts);
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
  std::vector<vtime*>*		__lts;
  vtime*			__ts;
  bool				__levaluate(Node* node);
  bool				__sevaluate(Node* node);
  bool				__tcmp(vtime ref, vtime* other);
};

#endif
