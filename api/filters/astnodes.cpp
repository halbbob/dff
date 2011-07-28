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
  while ((it != this->__values.end()) && !found)
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

StringFilter::StringFilter(const std::string& attr, CmpOperator::Op cmp, const std::string value) : __attr(attr)
{
  this->__etype = STRING;
  this->__cmp = cmp;
  this->__strvalues.push_back(value);
}

StringFilter::StringFilter(const std::string& attr, CmpOperator::Op cmp, const StringList& values) : __attr(attr)
{
  this->__etype = STRING;
  this->__cmp = cmp;
  this->__strvalues = values;
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
  	  ctx->setCaseSensitivity(Search::CaseSensitive);
  	  ctx->setPatternSyntax(Search::Fixed);
  	  ctx->setPattern(pattern);
  	}
      this->__ctxs.push_back(ctx);
    }
}

void		StringFilter::compile() throw (std::string)
{
  if (this->__etype == PROCESSOR)
    this->__pcompile();
  else if (this->__etype == STRING)
    this->__scompile();
  else
    throw (std::string("bad values type"));
}

bool		StringFilter::evaluate(Node* node) throw (std::string)
{
  StringList	values;
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
      if (this->__etype == PROCESSOR)
	return this->__pevaluate(values);
      else if (this->__etype == STRING)
	return this->__pevaluate(values);
      else
	return false;
    }
  else
    return false;
}

bool		StringFilter::__pevaluate(StringList values)
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
 if (this->__cmp == CmpOperator::EQ)
   return (found == true);
 else if (this->__cmp == CmpOperator::NEQ)
   return (found == false);
 return true;
}

bool		StringFilter::__sevaluate(StringList values)
{
  // StringList::iterator vit;
  // StringList::iterator cit;

  // for (vit = values.begin(); vit != values.end(); vit++)
  //   for (cit = this->__ctxs.begin(); cit != this->__cit.end(); cit++)
  //     if ((*cit)
  // return true;
}

uint32_t	StringFilter::cost()
{
  return 0;
}

BooleanFilter::BooleanFilter(const std::string& attr, CmpOperator::Op cmp, bool value) : __attr(attr)
{
  this->__cmp = cmp;
  this->__value = value;
}

void		BooleanFilter::compile() throw (std::string)
{
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
  return;
}

bool		TimeFilter::evaluate(Node* node) throw (std::string)
{
  return false;
}

uint32_t	TimeFilter::cost()
{
  return 0;
}


// MimeCmp::~MimeCmp()
// {
// }

// MimeCmp::MimeCmp(CmpOperator::Op cmp, std::string* str)
// {
//   this->__cmp = cmp;
//   this->__str = str;
//   this->__ctx = NULL;
//   this->__lstr = NULL;
//   this->__etype = SIMPLE;
// }

// MimeCmp::MimeCmp(CmpOperator::Op cmp, std::vector<std::string* >* lstr)
// {
//   this->__cmp = cmp;
//   this->__lstr = lstr;
//   this->__str = NULL;
//   this->__ctx = NULL;
//   this->__etype = LIST;
// }

// void		MimeCmp::compile() throw (std::string)
// {
//   std::vector<std::string*>::iterator	it;
//   Search*				ctx;

//   if (this->__etype == SIMPLE)
//     this->__ctx = this->__createCtx(this->__str);
//   else if (this->__etype == LIST)
//     {
//       this->__lctx = new std::vector<Search*>;
//       for (it = this->__lstr->begin(); it != this->__lstr->end(); it++)
// 	{
// 	  ctx = this->__createCtx(*it);
// 	  this->__lctx->push_back(ctx);
// 	}
//     }
//   else
//     ;
// }

// Search*		MimeCmp::__createCtx(std::string *str)
// {
//   Search*	ctx;
//   std::string	pattern;

//   ctx = new Search();
//   pattern = "*";
//   pattern += str->substr(1, str->size() - 2);
//   pattern += "*";
//   ctx->setPattern(pattern);
//   ctx->setPatternSyntax(Search::Wildcard);
//   ctx->setCaseSensitivity(Search::CaseInsensitive);
//   return ctx;
// }

// bool		MimeCmp::evaluate(Node* node) throw (std::string)
// {
//   if (this->__etype == SIMPLE)
//     return this->__sevaluate(node);
//   else if (this->__etype == LIST)
//     return this->__levaluate(node);
//   else
//     throw std::string("SizeCmp::evaluate() -> unknown eval type");
// }


// uint32_t	MimeCmp::cost()
// {
//   return 0;
// }

// bool		MimeCmp::__levaluate(Node* node)
// {
//   std::vector<std::string*>::iterator	it;
//   bool					found;
//   Variant*				datatype;

//   if (this->__lstr == NULL)
//     return false;
//   //std::cout << std::string(3, ' ') << node->size() << std::endl;
//   found = false;
//   it = this->__lstr->begin();
//   while ((it != this->__lstr->end()) && !found)
//     {
//       it++;
//     }
//   if (this->__cmp == CmpOperator::EQ)
//     return found == true;
//   else if (this->__cmp == CmpOperator::NEQ)
//     return found == false;
//   else
//     return false; //XXX throw bad op for in [] eval
// }

// bool		MimeCmp::__sevaluate(Node* node)
// {
//   std::map<std::string, Variant*>		vmap;
//   std::map<std::string, Variant*>::iterator	mit;
//   Variant*					datatypes;
//   bool						found;

//   if (this->__ctx == NULL)
//     return false; //XXX throw exception
//   datatypes = node->dataType();
//   if (datatypes == NULL)
//     return false;
//   vmap = datatypes->value<std::map<std::string, Variant*> >();
//   mit = vmap.begin();
//   found = false;
//   while ((mit != vmap.end()) && !found)
//     {
//       if (mit->second != NULL)
//   	{
//   	  if (this->__ctx->find(mit->second->toString()) != -1)
// 	    found = true;
//     	}
//       mit++;
//     }
//   if (this->__cmp == CmpOperator::EQ)
//     return found == true;
//   else if (this->__cmp == CmpOperator::NEQ)
//     return found == false;
//   else
//     return false; //XXX throw exception
// }



// NameCmp::~NameCmp()
// {
// }

// NameCmp::NameCmp(CmpOperator::Op cmp, Processor* proc)
// {
//   this->__cmp = cmp;
//   this->__proc = proc;
//   this->__lproc = NULL;
//   this->__ctx = NULL;
//   this->__etype = SIMPLE;
// }

// NameCmp::NameCmp(CmpOperator::Op cmp, std::vector<Processor* >* lproc)
// {
//   this->__cmp = cmp;
//   this->__lproc = lproc;
//   this->__proc = NULL;
//   this->__etype = LIST;
// }

// void			NameCmp::compile() throw (std::string)
// {
//   if (this->__etype == SIMPLE)
//     {
//       this->__ctx = this->__createCtx(this->__proc);
//       std::cout << this->__ctx->pattern() << std::endl;      
//     }
//   else if (this->__etype == LIST)
//     {
//     }
//   else
//     ;
// }

// bool			NameCmp::evaluate(Node* node) throw (std::string)
// {
//   if (this->__etype == SIMPLE)
//     return this->__sevaluate(node);
//   else if (this->__etype == LIST)
//     return this->__levaluate(node);
//   else
//     throw std::string("SizeCmp::evaluate() -> unknown eval type");
// }


// uint32_t		NameCmp::cost()
// {
//   return 0;
// }

// Search*				NameCmp::__createCtx(Processor* proc)
// {
//   Search*			ctx;
//   std::vector<std::string*>*	args;

//   ctx = new Search();
//   args = proc->arguments();
//   if (args->size() > 1)
//     ctx->setCaseSensitivity(Search::CaseInsensitive);
//   else
//     ctx->setCaseSensitivity(Search::CaseSensitive);
//   ctx->setPattern(args->at(0)->substr(1, args->at(0)->size() - 2));
//   if (proc->name()->compare("f") == 0)
//     ctx->setPatternSyntax(Search::Fixed);
//   else if (proc->name()->compare("w") == 0)
//     ctx->setPatternSyntax(Search::Wildcard);
//   else if (proc->name()->compare("re") == 0)
//     ctx->setPatternSyntax(Search::Regexp);
//   else if (proc->name()->compare("fz") == 0)
//     ctx->setPatternSyntax(Search::Fuzzy);
//   else
//     return NULL;
//   return ctx;
// }

// bool			NameCmp::__levaluate(Node* node)
// {
// }

// bool			NameCmp::__sevaluate(Node* node)
// {
//   bool	found;

//   if (this->__ctx == NULL)
//     return false; //XXX throw exception
//   found = false;
//   if (this->__ctx->find(node->name()) != -1)
//     found = true;
//   if (this->__cmp == CmpOperator::EQ)
//     return found == true;
//   else if (this->__cmp == CmpOperator::NEQ)
//     return found == false;
//   else
//     return false; //XXX throw exception  
// }


// TimeCmp::~TimeCmp()
// {
// }
 
// TimeCmp::TimeCmp(CmpOperator::Op cmp, vtime* ts)
// {
//   this->__cmp = cmp;
//   this->__ts = ts;
//   this->__lts = NULL;
//   this->__etype = SIMPLE;
// }

// TimeCmp::TimeCmp(CmpOperator::Op cmp, std::vector<vtime*>* lts)
// {
//   this->__cmp = cmp;
//   this->__lts = lts;
//   this->__ts = NULL;
//   this->__etype = LIST;
// }

// void		TimeCmp::compile() throw (std::string)
// {
//   return;
// }

// bool		TimeCmp::evaluate(Node* node) throw (std::string)
// {
//   if (this->__etype == SIMPLE)
//     return this->__sevaluate(node);
//   else if (this->__etype == LIST)
//     return this->__levaluate(node);
//   else
//     throw std::string("SizeCmp::evaluate() -> unknown eval type");
// }


// uint32_t	TimeCmp::cost()
// {
//   return 0;
// }

// bool		TimeCmp::__levaluate(Node* node)
// {
// }

// bool		TimeCmp::__sevaluate(Node* node)
// {
//   Attributes*		ts;
//   Attributes::iterator	mit;
//   vtime*		vt;
//   bool			found;

//   ts = node->attributesByType(typeId::VTime, ABSOLUTE_ATTR_NAME);
//   found = false;
//   mit = ts->begin();
//   while ((mit != ts->end()) && !found)
//     {
//       if (mit->second != NULL)
// 	{
// 	  if ((vt = mit->second->value<vtime*>()) != NULL)
// 	    {
// 	      //std::cout << mit->second->toString() << std::endl;
// 	      if (this->__tcmp(*vt, this->__ts))
// 		found = true;
// 	    }
// 	}
//       mit++;
//     }
//   return found;
// }

// bool		TimeCmp::__tcmp(vtime ref, vtime* ts)
// {
//   if (this->__cmp == CmpOperator::EQ)
//     if (ref == ts)
//       return true;
//     else
//       return false;
//   else if (this->__cmp == CmpOperator::NEQ)
//     if (ref != ts)
//       return true;
//     else
//       return false;
//   else if (this->__cmp == CmpOperator::GT)
//     {
//       if (ref > ts)
// 	return true;
//       else
// 	return false;
//     }
//   else if (this->__cmp == CmpOperator::LT)
//     if (ref < ts)
//       return true;
//     else
//       return false;
//   else if (this->__cmp == CmpOperator::GTE)
//     if (ref >= ts)
//       return true;
//     else
//       return false;
//   else if (this->__cmp == CmpOperator::LTE)
//     if (ref <= ts)
//       return true;
//     else
//       return false;
//   else
//     return false;
// }

// FileCmp::~FileCmp()
// {
// }

// FileCmp::FileCmp(CmpOperator::Op cmp, bool b)
// {
//   this->__b = b;
//   this->__cmp = cmp;  
// }

// void		FileCmp::compile() throw (std::string)
// {
//   return;
// }

// bool		FileCmp::evaluate(Node* node) throw (std::string)
// {
//   if (node != NULL)
//     {
//       if (this->__cmp == CmpOperator::EQ)
// 	if (node->size() > 0)
// 	  return true;
// 	else
// 	  return false;
//       else if (this->__cmp == CmpOperator::NEQ)
// 	if (node->size() == 0)
// 	  return true;
// 	else
// 	  return false;
//       else
// 	return false;
//     }
//   else
//     throw (std::string("provided node is NULL"));
// }


// uint32_t	FileCmp::cost()
// {
//   return 0;
// }


// DeletedCmp::~DeletedCmp()
// {
// }

// DeletedCmp::DeletedCmp(CmpOperator::Op cmp, bool b)
// {
//   this->__b = b;
//   this->__cmp = cmp;
// }

// void		DeletedCmp::compile() throw (std::string)
// {
//   return;
// }

// bool		DeletedCmp::evaluate(Node* node) throw (std::string)
// {
//   if (node != NULL)
//     {
//       if (this->__cmp == CmpOperator::EQ)
// 	if (node->isDeleted())
// 	  return true;
// 	else
// 	  return false;
//       else if (this->__cmp == CmpOperator::NEQ)
// 	if (!node->isDeleted())
// 	  return true;
// 	else
// 	  return false;
//       else
// 	return false;
//     }
//   else
//     throw (std::string("provided node is NULL"));
// }


// uint32_t	DeletedCmp::cost()
// {
//   return 0;
// }
