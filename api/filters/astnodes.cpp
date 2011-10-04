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


Processor::~Processor()
{
  this->__args.clear();
}

Processor::Processor(const std::string& name, const StringList& args): __name(name), __args(args)
{
}

std::string			Processor::name()
{
  return this->__name;
}

StringList	Processor::arguments()
{
  return this->__args;
};


Logical::Logical(AstNode* left, int op, AstNode* right)
{
  this->__left = left;
  this->__op = op;
  this->__right = right;
  if (this->__left != NULL)
    this->connection(this->__left);
  if (this->__right != NULL)
    this->connection(this->__right);
}

Logical::~Logical()
{
  if ((this->__left != NULL) && (this->__right != NULL))
    {
      this->deconnection(this->__left);
      this->deconnection(this->__right);
      delete this->__left;
      delete this->__right;
    }
}

uint32_t	Logical::cost() 
{
  return 0;
}

void		Logical::compile() throw (std::string)
{
  if ((this->__left != NULL) && (this->__right != NULL))
    {
      this->__left->compile();
      this->__right->compile();
    }
  else
    throw (std::string("Logical::compile(), left and right cannot be NULL"));
}

bool		Logical::evaluate(Node* node) throw (std::string)
{
  bool	ret = false;

  if (this->_stop)
    return false;
  if (this->__op == OR)
    {
      if (this->__left->cost() < this->__right->cost())
	{
	  if (((ret = this->__left->evaluate(node)) == false) && !this->_stop)
	    ret = this->__right->evaluate(node);
	}
      else
	{
	  if (((ret = this->__right->evaluate(node)) == false) && !this->_stop)
	    ret = this->__left->evaluate(node);
	}
    }
  else if (this->__op == AND)
    {
      if (this->__left->evaluate(node) && !this->_stop)
	ret = this->__right->evaluate(node);
      else
	ret = false;
    }
  else
    std::cout << "bad operator" << std::endl;//throw std::string("operator not managed");
  return ret;
}

NumericFilter::~NumericFilter()
{
  this->__rvalues.clear();
}

NumericFilter::NumericFilter(const std::string& attr, CmpOperator::Op cmp, uint64_t value) : __attr(attr)
{
  this->__cmp = cmp;
  this->__rvalues.push_back(value);
}

NumericFilter::NumericFilter(const std::string& attr, CmpOperator::Op cmp, const NumberList& values) : __attr(attr), __rvalues(values)
{
  this->__cmp = cmp;
}

void		NumericFilter::compile() throw (std::string)
{
  if (this->__attr != "size")
    {
      this->__attr = this->__attr.substr(1, this->__attr.size() - 2);
      if (this->__attr.find(".") != std::string::npos)
	this->__tname = ABSOLUTE_ATTR_NAME;
      else
	this->__tname = RELATIVE_ATTR_NAME;
    }
  else
    this->__tname = ABSOLUTE_ATTR_NAME;
  return;
}

bool		NumericFilter::evaluate(Node* node) throw (std::string)
{
  uint64_t	lvalue;
  bool		process;
  Variant*	v;
  VLIST		vlist;
  
  // std::cout << "attribute: " << this->__attr << std::endl;
  // std::cout << "comparison: " << this->__cmp << std::endl;
  process = false;
  v = NULL;
  if (this->_stop)
    return false;
  if (this->__attr == "size")
    {
      lvalue = node->size();
      process = true;
    }
  else
    {
      try
	{
	  if ((v = node->attributesByName(this->__attr, this->__tname)) != NULL)
	    {
	      if (this->__tname == ABSOLUTE_ATTR_NAME)
		lvalue = v->value<uint64_t>();
	      else
		{
		  vlist = v->value< VLIST >();
		  if (vlist.size() == 1 && vlist.front() != NULL)
		    lvalue = vlist.front()->value<uint64_t>();
		  vlist.clear();		  
		}
	      delete v;
	      process = true;
	    }
	}
      catch (std::string err)
	{
	  vlist.clear();
	  if (v != NULL)
	    delete v;
	}
    }
  if (process && !this->_stop)
    if (this->__rvalues.size() == 1)
      return this->__sevaluate(lvalue, this->__rvalues[0]);
    else
      return this->__levaluate(lvalue);
  else
    return false;
}

bool		NumericFilter::__levaluate(uint64_t lvalue)
{
  NumberList::iterator		it;
  bool				found;

  found = false;
  it = this->__rvalues.begin();
  while ((it != this->__rvalues.end()) && (!found) && (!this->_stop))
    {
      if (lvalue == *it)
	found = true;
      it++;
    }
  if (this->__cmp == CmpOperator::EQ)
    return (found == true);
  else if (this->__cmp == CmpOperator::NEQ)
    return (found == false);
  else
    return false;
}

bool		NumericFilter::__sevaluate(uint64_t lvalue, uint64_t rvalue)
{
  if (this->__cmp == CmpOperator::EQ)
    if (lvalue == rvalue)
      return true;
    else
      return false;
  else if (this->__cmp == CmpOperator::NEQ)
    if (lvalue != rvalue)
      return true;
    else
      return false;
  else if (this->__cmp == CmpOperator::LT)
    if (lvalue < rvalue)
      return true;
    else
      return false;
  else if (this->__cmp == CmpOperator::LTE)
    if (lvalue <= rvalue)
      return true;
    else
      return false;
  else if (this->__cmp == CmpOperator::GT)
    if (lvalue > rvalue)
      return true;
    else
      return false;
  else if (this->__cmp == CmpOperator::GTE)
    if (lvalue >= rvalue)
      return true;
    else
      return false;
  else
    return false;
}

uint32_t	NumericFilter::cost()
{
  return 0;
}

StringFilter::~StringFilter()
{
  std::vector<Search*>::iterator	it;

  for (it = this->__ctxs.begin(); it != this->__ctxs.end(); it++)
    delete *it;
  if (this->__proc != NULL)
    delete this->__proc;
}

StringFilter::StringFilter(const std::string& attr, CmpOperator::Op cmp, const std::string value) : __attr(attr)
{
  this->__etype = STRING;
  this->__cmp = cmp;
  this->__strvalues.push_back(value);
  this->__proc = NULL;
}

StringFilter::StringFilter(const std::string& attr, CmpOperator::Op cmp, const StringList& values) : __attr(attr)
{
  this->__etype = STRING;
  this->__cmp = cmp;
  this->__strvalues = values;
  this->__proc = NULL;
}

StringFilter::StringFilter(const std::string& attr, CmpOperator::Op cmp, Processor* value) : __attr(attr)
{
  this->__etype = PROCESSOR;
  this->__cmp = cmp;
  this->__proc = value;
}

void		StringFilter::__pcompile()
{
  Search*	ctx;
  StringList	args;
  std::string	pattern;

  ctx = new Search;
  args = this->__proc->arguments();
  if (args.size() > 1)
    ctx->setCaseSensitivity(Search::CaseInsensitive);
  else
    ctx->setCaseSensitivity(Search::CaseSensitive);
  pattern = args[0].substr(1, args[0].size() - 2);
  ctx->setPattern(pattern);
  if (this->__proc->name() == "f")
    ctx->setPatternSyntax(Search::Fixed);
  else if (this->__proc->name() == "w")
    ctx->setPatternSyntax(Search::Wildcard);
  else if (this->__proc->name() == "re")
    ctx->setPatternSyntax(Search::Regexp);
  else if (this->__proc->name() == "fz")
    ctx->setPatternSyntax(Search::Fuzzy);
  ctx->compile();
  this->__ctxs.push_back(ctx);
}

void		StringFilter::__scompile()
{
  Search*		ctx;
  StringList::iterator	it;
  std::string		pattern; 
 
  for (it = this->__strvalues.begin(); it != this->__strvalues.end(); it++)
    {
      ctx = new Search;
      if (this->__attr == "mime")
  	{
  	  pattern = (*it).substr(1, (*it).size() - 2);
  	  ctx->setCaseSensitivity(Search::CaseInsensitive);
  	  ctx->setPatternSyntax(Search::Fixed);
  	  ctx->setPattern(pattern);
  	}
      else
  	{
  	  pattern = (*it).substr(1, (*it).size() - 2);
	  if (this->__attr == "data")
	    {
	      ctx->setPatternSyntax(Search::Fuzzy);
	      ctx->setCaseSensitivity(Search::CaseInsensitive);
	    }
	  else
	    {
	      ctx->setPatternSyntax(Search::Fixed);
	      ctx->setCaseSensitivity(Search::CaseSensitive);
	    }
  	  ctx->setPattern(pattern);
  	}
      ctx->compile();
      this->__ctxs.push_back(ctx);
    }
}

void		StringFilter::compile() throw (std::string)
{
  if ((this->__attr != "mime") && (this->__attr != "name") && (this->__attr != "data"))
    {
      this->__attr = this->__attr.substr(1, this->__attr.size() - 2);
      if (this->__attr.find(".") != std::string::npos)
	this->__tname = ABSOLUTE_ATTR_NAME;
      else
	this->__tname = RELATIVE_ATTR_NAME;
    }
  else
    this->__tname = ABSOLUTE_ATTR_NAME;
  if (this->__etype == PROCESSOR)
    this->__pcompile();
  else if (this->__etype == STRING)
    this->__scompile();
  else
    throw (std::string("bad values type"));
}

bool		StringFilter::evaluate(Node* node) throw (std::string)
{
  StringList		values;
  Attributes		vmap;
  Attributes::iterator	it;
  Variant*		v;
  bool			process;
  VLIST			vlist;

  v = NULL;
  process = false;
  if (this->_stop)
    return false;
  if (this->__attr == "name")
    {
      values.push_back(node->name());
      process = true;
    }
  else if (this->__attr == "data")
    process = true;
  else if (this->__attr == "mime")
    {
      try
	{
	  if ((v = node->dataType()) != NULL)
	    {
	      vmap = v->value<Attributes>();
	      if (((it = vmap.find("magic mime")) != vmap.end()) && (it->second != NULL) && (it->second->type() == typeId::String))
		{
		  values.push_back(it->second->value<std::string>());
		  process = true;
		}
	      vmap.clear();
	      delete v;
	    }
	}
      catch (...)
	{
	  if (v != NULL)
	    delete v;
	}
    }
  else
    {
      try
	{
	  if ((v = node->attributesByName(this->__attr, this->__tname)) != NULL)
	    {
	      if (this->__tname == ABSOLUTE_ATTR_NAME && v->type() == typeId::String)
		{
		  values.push_back(v->value<std::string>());
		  process = true;
		}
	      else if (this->__tname == RELATIVE_ATTR_NAME && v->type() == typeId::List)
		{
		  vlist = v->value< VLIST >();
		  Variant*	vptr;
		  if ((vlist.size() == 1) && (((vptr = vlist.front()) != NULL) && (vptr->type() == typeId::String)))
		    {
		      values.push_back(vptr->value< std::string >());
		      process = true;
		    }
		  vlist.clear();
		}
	      else
		delete v;
	    }
	}
      catch (...)
	{
	  vlist.clear();
	  if (v != NULL)
	    delete v;
	}
    }
  if (process && !this->_stop)
    {
      bool	ret;
      if (this->__attr == "data")
	ret = this->__devaluate(node);
      else
	ret = this->__sevaluate(values);
      values.clear();
      if (this->__cmp == CmpOperator::EQ)
	return (ret == true);
      else if (this->__cmp == CmpOperator::NEQ)
	return (ret == false);
      else
	return false;
    }
  else
    return false;
}

bool		StringFilter::__sevaluate(const StringList& values)
{
 StringList::const_iterator		vit;
 std::vector<Search*>::iterator		cit;
 bool					found;
 
 found = false;
 vit = values.begin();
 while (vit != values.end() && !this->_stop)
   {
     cit = this->__ctxs.begin();
     while (cit != this->__ctxs.end() && !this->_stop)
       {
	 if ((*cit)->find(*vit) != -1)
	   found = true;
	 cit++;
       }
     vit++;
   }
 return found;
}


bool		StringFilter::__devaluate(Node* node)
{
  VFile*				v;
  std::vector<Search*>::iterator	cit;
  bool					found;
  int64_t				idx;

  found = false;
  v = NULL;
  if (node->size() == 0)
    return found;
  try
    {
      if ((v = node->open()) != NULL)
	{
	  this->connection(v);
	  cit = this->__ctxs.begin();
	  while (cit != this->__ctxs.end() && !this->_stop)
	    {
	      if ((idx = v->find(*cit)) != -1)
		found = true;
	      cit++;
	    }
	  this->deconnection(v);
	}
    }
  catch (vfsError err)
    {
    }
  if (v != NULL)
    delete v;
  return found;
}

uint32_t	StringFilter::cost()
{
  return 0;
}

BooleanFilter::~BooleanFilter()
{
}

BooleanFilter::BooleanFilter(const std::string& attr, CmpOperator::Op cmp, bool value) : __attr(attr)
{
  this->__cmp = cmp;
  this->__val = value;
}

void		BooleanFilter::compile() throw (std::string)
{
  if ((this->__attr != "deleted") && (this->__attr != "file"))
    {
      this->__attr = this->__attr.substr(1, this->__attr.size() - 2);
      if (this->__attr.find(".") != std::string::npos)
	this->__tname = ABSOLUTE_ATTR_NAME;
      else
	this->__tname = RELATIVE_ATTR_NAME;
    }
  else
    this->__tname = ABSOLUTE_ATTR_NAME;
  return;
}

bool		BooleanFilter::evaluate(Node* node) throw (std::string)
{
  bool		value;
  bool		process;
  Variant*	v;
  VLIST		vlist;

  process = false;
  v = NULL;
  if (this->_stop)
    return false;
  if (this->__attr == "deleted")
    {
      value = node->isDeleted();
      process = true;
    }
  else if (this->__attr == "file")
    {
      if (node->size() > 0)
	value = true;
      else
	value = false;
      process = true;
    }
  else
    {
      try
	{
	  if ((v = node->attributesByName(this->__attr, this->__tname)) != NULL)
	    {
	      if (this->__tname == ABSOLUTE_ATTR_NAME && v->type() == typeId::Bool)
		{
		  value = v->value< bool >();
		  process = true;
		}
	      else if (this->__tname == RELATIVE_ATTR_NAME && v->type() == typeId::List)
		{
		  vlist = v->value< VLIST >();
		  Variant*	vptr;
		  if ((vlist.size() == 1) && (((vptr = vlist.front()) != NULL) && (vptr->type() == typeId::Bool)))
		    {
		      value = vptr->value< bool >();
		      process = true;
		    }
		  vlist.clear();
		}
	      delete v;
	    }
	}
      catch (...)
	{
	  vlist.clear();
	  if (v != NULL)
	    delete v;
	}
    }
  if (process && !this->_stop)
    {
      if (this->__cmp == CmpOperator::EQ)
	return (value == this->__val);
      else if (this->__cmp == CmpOperator::NEQ)
	return (value != this->__val);
      else
	return false;
    }
  else
    return false;
}

uint32_t	BooleanFilter::cost()
{
  return 0;
}

TimeFilter::~TimeFilter()
{
  TimeList::iterator	it;

  for (it = this->__values.begin(); it != this->__values.end(); it++)
    delete *it;
}


TimeFilter::TimeFilter(const std::string& attr, CmpOperator::Op cmp, vtime* value) : __attr(attr)
{
  this->__cmp = cmp;
  this->__values.push_back(value);
}

TimeFilter::TimeFilter(const std::string& attr, CmpOperator::Op cmp, const TimeList& values) : __attr(attr), __values(values)
{
  this->__cmp = cmp;
}

void		TimeFilter::compile() throw (std::string)
{
  if (this->__attr != "time")
    {
      this->__attr = this->__attr.substr(1, this->__attr.size() - 2);
      if (this->__attr.find(".") != std::string::npos)
	this->__tname = ABSOLUTE_ATTR_NAME;
      else
	this->__tname = RELATIVE_ATTR_NAME;
    }
  else
    this->__tname = ABSOLUTE_ATTR_NAME;
  return;
}

bool		TimeFilter::evaluate(Node* node) throw (std::string)
{
  Attributes*		ts;
  Attributes::iterator	mit;
  vtime*		vt;
  bool			found;
  Variant		*v;
  VLIST			vlist;

  found = false;
  v = NULL;
  ts = NULL;
  vt = NULL;
  if (this->_stop)
    return false;
  if (this->__attr == "time")
    {
      try
	{
	  if ((ts = node->attributesByType(typeId::VTime, ABSOLUTE_ATTR_NAME)) != NULL)
	    {
	      mit = ts->begin();
	      while ((mit != ts->end()) && !found && !this->_stop)
		{
		  if ((mit->second != NULL) && ((vt = mit->second->value<vtime*>()) != NULL))
		    found = this->__evaluate(vt);
		  mit++;
		}
	    }
	}
      catch (...)
	{
	}
    }
  else
    {
      try
	{
	  if ((v = node->attributesByName(this->__attr, this->__tname)) != NULL)
	    {
	      if (this->__tname == ABSOLUTE_ATTR_NAME && v->type() == typeId::VTime)
		found = this->__evaluate(v->value<vtime*>());
	      else if (this->__tname == RELATIVE_ATTR_NAME && v->type() == typeId::List)
		{
		  vlist = v->value< VLIST >();
		  Variant	*vptr;
		  if (vlist.size() == 1 && (((vptr = vlist.front()) != NULL) && (vptr->type() == typeId::VTime)))
		    found = this->__evaluate(vptr->value<vtime*>());
		}
	      vlist.clear();
	    }
	}
      catch (...)
	{
	}
    }
  vlist.clear();
  if (v != NULL)
    delete v;
  if (ts != NULL)
    delete ts;
  if (this->__values.size() > 1)
    if (this->__cmp == CmpOperator::EQ)
      return (found == true);
    else if (this->__cmp == CmpOperator::NEQ)
      return (found == false);
    else
      return false;
  else
    return found;
}

uint32_t	TimeFilter::cost()
{
  return 0;
}


bool		TimeFilter::__evaluate(vtime* vt)
{
  TimeList::iterator	it;
  bool			found;

  found = false;
  it = this->__values.begin();
  while ((it != this->__values.end()) && !found && !this->_stop)
    {
      if (this->__tcmp(*vt, *it))
	found = true;
      it++;
    }
  return found;
}

bool		TimeFilter::__tcmp(vtime ref, vtime* ts)
{
  if (this->__cmp == CmpOperator::EQ)
    if (ref == ts)
      return true;
    else
      return false;
  else if (this->__cmp == CmpOperator::NEQ)
    if (ref != ts)
      return true;
    else
      return false;
  else if (this->__cmp == CmpOperator::GT)
    {
      if (ref > ts)
	return true;
      else
	return false;
    }
  else if (this->__cmp == CmpOperator::LT)
    if (ref < ts)
      return true;
    else
      return false;
  else if (this->__cmp == CmpOperator::GTE)
    if (ref >= ts)
      return true;
    else
      return false;
  else if (this->__cmp == CmpOperator::LTE)
    if (ref <= ts)
      return true;
    else
      return false;
  else
    return false;
}
