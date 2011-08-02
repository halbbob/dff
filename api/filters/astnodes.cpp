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
}

Logical::~Logical()
{
  if ((this->__left != NULL) && (this->__right != NULL))
    {
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
  this->_stop = false;
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
	  if ((ret = this->__left->evaluate(node)) == false)
	    ret = this->__right->evaluate(node);
	}
      else
	{
	  if ((ret = this->__right->evaluate(node)) == false)
	    ret = this->__left->evaluate(node);
	}
    }
  else if (this->__op == AND)
    {
      if (this->__left->evaluate(node) && this->__right->evaluate(node))
	ret = true;
      else
	ret = false;
    }
  else
    std::cout << "bad operator" << std::endl;//throw std::string("operator not managed");
  return ret;
}

NumericFilter::~NumericFilter()
{
  this->__values.clear();
}

NumericFilter::NumericFilter(const std::string& attr, CmpOperator::Op cmp, uint64_t value) : __attr(attr)
{
  this->__cmp = cmp;
  this->__values.push_back(value);
}

NumericFilter::NumericFilter(const std::string& attr, CmpOperator::Op cmp, const NumberList& values) : __attr(attr), __values(values)
{
  this->__cmp = cmp;
}

void		NumericFilter::compile() throw (std::string)
{
  this->_stop = false;
  if (this->__attr != "size")
    this->__attr = this->__attr.substr(1, this->__attr.size() - 2);
  return;
}

bool		NumericFilter::evaluate(Node* node) throw (std::string)
{
  uint64_t	value;
  bool		process;
  Variant*	v;
  
  // std::cout << "attribute: " << this->__attr << std::endl;
  // std::cout << "comparison: " << this->__cmp << std::endl;
  process = false;
  if (this->__attr == "size")
    {
      value = node->size();
      process = true;
    }
  else
    {
      if ((v = node->attributesByName(this->__attr, ABSOLUTE_ATTR_NAME)) != NULL)
	{
	  try
	    {
	      value = v->value<uint64_t>();
	      delete v;
	      process = true;
	    }
	  catch (std::string err)
	    {
	      delete v;
	      throw err;
	    }
	}
    }
  if (process)
    if (this->__values.size() == 1)
      return this->__evaluate(value, this->__values[0]);
    else
      return this->__levaluate(value);
  else
    return false;
}

bool		NumericFilter::__levaluate(uint64_t value)
{
  NumberList::iterator	it;
  bool			found;

  it = this->__values.begin();
  found = false;
  while ((it != this->__values.end()) && (!found) && (!this->_stop))
    {
      if (value == *it)
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

bool		NumericFilter::__evaluate(uint64_t value, uint64_t provided)
{
  if (this->__cmp == CmpOperator::EQ)
    if (value == provided)
      return true;
    else
      return false;
  else if (this->__cmp == CmpOperator::NEQ)
    if (value != provided)
      return true;
    else
      return false;
  else if (this->__cmp == CmpOperator::LT)
    if (value < provided)
      return true;
    else
      return false;
  else if (this->__cmp == CmpOperator::LTE)
    if (value <= provided)
      return true;
    else
      return false;
  else if (this->__cmp == CmpOperator::GT)
    if (value > provided)
      return true;
    else
      return false;
  else if (this->__cmp == CmpOperator::GTE)
    if (value >= provided)
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
  	  pattern = "*" + (*it).substr(1, (*it).size() - 2) + "*";
  	  ctx->setCaseSensitivity(Search::CaseInsensitive);
  	  ctx->setPatternSyntax(Search::Wildcard);
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
      this->__ctxs.push_back(ctx);
    }
}

void		StringFilter::compile() throw (std::string)
{
  this->_stop = false;
  if ((this->__attr != "mime") && (this->__attr != "name") && (this->__attr != "data"))
    this->__attr = this->__attr.substr(1, this->__attr.size() - 2);
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
  Attributes::iterator	mit;
  Variant*		v;
  bool			process;
  
  if (this->__attr == "name")
    {
      //std::cout << "GOT NAME" << std::endl;
      values.push_back(node->name());
      process = true;
    }
  else if (this->__attr == "data")
    process = true;
  else if (this->__attr == "mime")
    {
      //std::cout << "GOT MIME" << std::endl;
      if ((v = node->dataType()) != NULL)
	{
	  vmap = v->value<Attributes>();
	  for (mit = vmap.begin(); mit != vmap.end(); mit++)
	    if (mit->second != NULL)
	      {
		try
		  {
		    values.push_back(mit->second->value<std::string>());
		  }
		catch (std::string err)
		  {
		    throw err;
		  }
	      }
	  process = true;
	}
    }
  else
    {
      if ((v = node->attributesByName(this->__attr, ABSOLUTE_ATTR_NAME)) != NULL)
	if (v->type() == typeId::String)
	  values.push_back(v->value<std::string>());
    }
  if (process)
    {
      bool	ret;
      if (this->__attr == "data")
	ret = this->__devaluate(node);
      else
	ret = this->__sevaluate(values);
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

bool		StringFilter::__sevaluate(StringList values)
{
 StringList::iterator			vit;
 std::vector<Search*>::iterator		cit;
 bool					found;
 
 found = false;
 for (vit = values.begin(); vit != values.end(); vit++)
   for (cit = this->__ctxs.begin(); cit != this->__ctxs.end(); cit++)
     if ((*cit)->find(*vit) != -1)
       found = true;
 //std::cout << "FOUND ---> " << found << std::endl;
 return found;
}


bool		StringFilter::__devaluate(Node* node)
{
  VFile*				v;
  std::vector<Search*>::iterator	cit;
  bool					found;
  int64_t				idx;

  found = false;
  if (node->size() == 0)
    return found;
  if ((v = node->open()) != NULL)
    {
      cit = this->__ctxs.begin();
      while (cit != this->__ctxs.end() && !this->_stop)
	{
	  if ((idx = v->find(*cit)) != -1)
	    {
	      found = true;
	      //std::cout << (*cit)->pattern() << " FOUND in " << node->absolute() << " @ " << idx << std::endl;
	    }
	  cit++;
	}
    }
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
  this->__value = value;
}

void		BooleanFilter::compile() throw (std::string)
{
  if ((this->__attr != "deleted") && (this->__attr != "file"))
    this->__attr = this->__attr.substr(1, this->__attr.size() - 2);
  return;
}

bool		BooleanFilter::evaluate(Node* node) throw (std::string)
{
  bool		value;
  bool		process;
  Variant*	v;

  process = false;
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
  else if ((v = node->attributesByName(this->__attr, ABSOLUTE_ATTR_NAME)) != NULL)
    {
      if (v->type() == typeId::Bool)
	{
	  value = v->value<bool>();
	  process = true;
	}
    }
  if (process)
    {
      if (this->__cmp == CmpOperator::EQ)
	return (value == this->__value);
      else if (this->__cmp == CmpOperator::NEQ)
	return (value != this->__value);
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
    this->__attr = this->__attr.substr(1, this->__attr.size() - 2);
  return;
}

bool		TimeFilter::evaluate(Node* node) throw (std::string)
{
  Attributes*		ts;
  Attributes::iterator	mit;
  vtime*		vt;
  bool			found;
  Variant		*v;

  found = false;
  if (this->__attr == "time")
    {
      if ((ts = node->attributesByType(typeId::VTime, ABSOLUTE_ATTR_NAME)) == NULL)
	return false;
      else
	{
	  mit = ts->begin();
	  while ((mit != ts->end()) && !found)
	    {
	      if ((mit->second != NULL) && ((vt = mit->second->value<vtime*>()) != NULL))
		found = this->__evaluate(vt);
	      mit++;
	    }
	}
    }
  else
    {
      if (((v = node->attributesByName(this->__attr, ABSOLUTE_ATTR_NAME)) == NULL) ||
	  (v->type() != typeId::VTime))
	return false;
      else
	found = this->__evaluate(v->value<vtime*>());
    }
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
  while ((it != this->__values.end()) && !found)
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