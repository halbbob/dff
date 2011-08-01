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
#include "eventhandler.hpp"


typedef std::vector<uint64_t>		NumberList;
typedef std::vector<std::string>	StringList;
typedef std::vector<vtime*>		TimeList;

class Processor
{
public:
  ~Processor();
  Processor(const std::string& name, const StringList& args);
  std::string		name();
  StringList		arguments();
private:
  std::string		__name;
  StringList		__args;
};

typedef std::vector<Processor*>		ProcessorList;

class AstNode : public EventHandler
{
public:
  typedef enum
    {
      NUMERIC,
      STRING,
      BOOLEAN,
      TIMESTAMP,
      LOGIC
    }	Type;
  virtual ~AstNode() { _stop = false; }
  virtual void		compile() throw (std::string) = 0;
  virtual bool		evaluate(Node* node) throw (std::string) = 0;
  virtual uint32_t	cost() = 0;
  virtual Type		type() = 0;
  virtual void		Event(event* e) { _stop = true; }
protected:
  bool			_stop;
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
  bool		__stop;
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
  AstNode::Type		type() { return AstNode::LOGIC; }
};


class NumericFilter: public AstNode
{
public:
  NumericFilter(const std::string& attr, CmpOperator::Op cmp, uint64_t value);
  NumericFilter(const std::string& attr, CmpOperator::Op cmp, const NumberList& values);
  virtual void		compile() throw (std::string);
  virtual bool		evaluate(Node* node) throw (std::string);
  virtual uint32_t	cost();
  AstNode::Type		type() { return AstNode::NUMERIC; }
private:
  CmpOperator::Op	__cmp;
  uint32_t		__cost;
  std::string		__attr;
  NumberList		__values;
  bool			__evaluate(uint64_t value, uint64_t provided);
  bool			__levaluate(uint64_t value);
};


class StringFilter: public AstNode
{
public:
  StringFilter(const std::string& attr, CmpOperator::Op cmp, const std::string value);
  StringFilter(const std::string& attr, CmpOperator::Op cmp, const StringList& values);
  StringFilter(const std::string& attr, CmpOperator::Op cmp, Processor* value);
  virtual void		compile() throw (std::string);
  virtual bool		evaluate(Node* node) throw (std::string);
  virtual uint32_t	cost();
  AstNode::Type		type() { return AstNode::STRING; }
private:
  enum EType
    {
      STRING,
      PROCESSOR
    };
  EType			__etype;
  CmpOperator::Op	__cmp;
  uint32_t		__cost;
  std::string		__attr;
  StringList		__strvalues;
  Processor*		__proc;
  std::vector<Search*>	__ctxs;
  void			__pcompile();
  void			__scompile();
  bool			__sevaluate(StringList values);
  bool			__devaluate(Node* node);
};

class BooleanFilter: public AstNode
{
public:
  BooleanFilter(const std::string& attr, CmpOperator::Op cmp, bool value);
  virtual void		compile() throw (std::string);
  virtual bool		evaluate(Node* node) throw (std::string);
  virtual uint32_t	cost();
  AstNode::Type		type() { return AstNode::BOOLEAN; }
private:
  CmpOperator::Op	__cmp;
  uint32_t		__cost;
  std::string		__attr;
  bool			__value;
};

class TimeFilter: public AstNode
{
public:
  TimeFilter(const std::string& attr, CmpOperator::Op cmp, vtime* value);
  TimeFilter(const std::string& attr, CmpOperator::Op cmp, const TimeList& values);
  virtual void		compile() throw (std::string);
  virtual bool		evaluate(Node* node) throw (std::string);
  virtual uint32_t	cost();
  AstNode::Type		type() { return AstNode::TIMESTAMP; }
private:
  CmpOperator::Op	__cmp;
  uint32_t		__cost;
  std::string		__attr;
  TimeList		__values;
  bool			__tcmp(vtime v1, vtime* v2);
};

#endif
