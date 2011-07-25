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
  std::vector<std::string*>::iterator it;
  
  delete this->__name;
  for (it = this->__args->begin(); it != this->__args->end(); it++)
    delete *it;
  delete this->__args;
}

Processor::Processor(std::string* name, std::vector<std::string*>* args)
{
  this->__name = name;
  this->__args = args;
}

std::string*			Processor::name()
{
  return this->__name;
}

std::vector<std::string*>*	Processor::arguments()
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

void		SizeCmp::compile() throw (std::string)
{
  return;
}

bool		SizeCmp::__levaluate(Node* node)
{
  std::vector<uint64_t>::iterator	it;
  bool					found;

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


MimeCmp::~MimeCmp()
{
}

MimeCmp::MimeCmp(CmpOperator::Op cmp, std::string* str)
{
  this->__cmp = cmp;
  this->__str = str;
  this->__ctx = NULL;
  this->__lstr = NULL;
  this->__etype = SIMPLE;
}

MimeCmp::MimeCmp(CmpOperator::Op cmp, std::vector<std::string* >* lstr)
{
  this->__cmp = cmp;
  this->__lstr = lstr;
  this->__str = NULL;
  this->__ctx = NULL;
  this->__etype = LIST;
}

void		MimeCmp::compile() throw (std::string)
{
  std::vector<std::string*>::iterator	it;
  Search*				ctx;

  if (this->__etype == SIMPLE)
    this->__ctx = this->__createCtx(this->__str);
  else if (this->__etype == LIST)
    {
      this->__lctx = new std::vector<Search*>;
      for (it = this->__lstr->begin(); it != this->__lstr->end(); it++)
	{
	  ctx = this->__createCtx(*it);
	  this->__lctx->push_back(ctx);
	}
    }
  else
    ;
}

Search*		MimeCmp::__createCtx(std::string *str)
{
  Search*	ctx;

  ctx = new Search();
  ctx->setPattern(str->substr(1, str->size() - 2));
  ctx->setPatternSyntax(Search::Wildcard);
  ctx->setCaseSensitivity(Search::CaseInsensitive);
  return ctx;
}

bool		MimeCmp::evaluate(Node* node) throw (std::string)
{
  if (this->__etype == SIMPLE)
    return this->__sevaluate(node);
  else if (this->__etype == LIST)
    return this->__levaluate(node);
  else
    throw std::string("SizeCmp::evaluate() -> unknown eval type");
}

bool		MimeCmp::evaluate(Node* node, int depth) throw (std::string)
{
  if (this->__etype == SIMPLE)
    return this->__sevaluate(node);
  else if (this->__etype == LIST)
    return this->__levaluate(node);
  else
    throw std::string("SizeCmp::evaluate() -> unknown eval type");
}

uint32_t	MimeCmp::cost()
{
  return 0;
}

bool		MimeCmp::__levaluate(Node* node)
{
  std::vector<std::string*>::iterator	it;
  bool					found;
  Variant*				datatype;

  if (this->__lstr == NULL)
    return false;
  //std::cout << std::string(3, ' ') << node->size() << std::endl;
  found = false;
  it = this->__lstr->begin();
  while ((it != this->__lstr->end()) && !found)
    {
      it++;
    }
  if (this->__cmp == CmpOperator::EQ)
    return found == true;
  else if (this->__cmp == CmpOperator::NEQ)
    return found == false;
  else
    return false; //XXX throw bad op for in [] eval
}

bool		MimeCmp::__sevaluate(Node* node)
{
  std::map<std::string, Variant*>		vmap;
  std::map<std::string, Variant*>::iterator	mit;
  Variant*					datatypes;
  bool						found;

  if (this->__ctx == NULL)
    return false; //XXX throw exception
  datatypes = node->dataType();
  if (datatypes == NULL)
    return false;
  vmap = datatypes->value<std::map<std::string, Variant*> >();
  mit = vmap.begin();
  found = false;
  while ((mit != vmap.end()) && !found)
    {
      if (mit->second != NULL)
  	{
  	  if (this->__ctx->find(mit->second->toString()) != -1)
	    found = true;
    	}
      mit++;
    }
  if (this->__cmp == CmpOperator::EQ)
    return found == true;
  else if (this->__cmp == CmpOperator::NEQ)
    return found == false;
  else
    return false; //XXX throw exception
}



NameCmp::~NameCmp()
{
}

NameCmp::NameCmp(CmpOperator::Op cmp, Processor* proc)
{
  this->__cmp = cmp;
  this->__proc = proc;
  this->__lproc = NULL;
  this->__ctx = NULL;
  this->__etype = SIMPLE;
}

NameCmp::NameCmp(CmpOperator::Op cmp, std::vector<Processor* >* lproc)
{
  this->__cmp = cmp;
  this->__lproc = lproc;
  this->__proc = NULL;
  this->__etype = LIST;
}

void			NameCmp::compile() throw (std::string)
{
  if (this->__etype == SIMPLE)
    {
      this->__ctx = this->__createCtx(this->__proc);
      std::cout << this->__ctx->pattern() << std::endl;      
    }
  else if (this->__etype == LIST)
    {
    }
  else
    ;
}

bool			NameCmp::evaluate(Node* node) throw (std::string)
{
  if (this->__etype == SIMPLE)
    return this->__sevaluate(node);
  else if (this->__etype == LIST)
    return this->__levaluate(node);
  else
    throw std::string("SizeCmp::evaluate() -> unknown eval type");
}

bool			NameCmp::evaluate(Node* node, int depth) throw (std::string)
{
  if (this->__etype == SIMPLE)
    return this->__sevaluate(node);
  else if (this->__etype == LIST)
    return this->__levaluate(node);
  else
    throw std::string("SizeCmp::evaluate() -> unknown eval type");
}

uint32_t		NameCmp::cost()
{
  return 0;
}

Search*				NameCmp::__createCtx(Processor* proc)
{
  Search*			ctx;
  std::vector<std::string*>*	args;

  ctx = new Search();
  args = proc->arguments();
  if (args->size() > 1)
    ctx->setCaseSensitivity(Search::CaseInsensitive);
  else
    ctx->setCaseSensitivity(Search::CaseSensitive);
  ctx->setPattern(args->at(0)->substr(1, args->at(0)->size() - 2));
  if (proc->name()->compare("f") == 0)
    ctx->setPatternSyntax(Search::Fixed);
  else if (proc->name()->compare("w") == 0)
    ctx->setPatternSyntax(Search::Wildcard);
  else if (proc->name()->compare("re") == 0)
    ctx->setPatternSyntax(Search::Regexp);
  else if (proc->name()->compare("fz") == 0)
    ctx->setPatternSyntax(Search::Fuzzy);
  else
    return NULL;
  return ctx;
}

bool			NameCmp::__levaluate(Node* node)
{
}

bool			NameCmp::__sevaluate(Node* node)
{
  bool	found;

  if (this->__ctx == NULL)
    return false; //XXX throw exception
  found = false;
  if (this->__ctx->find(node->name()) != -1)
    found = true;
  if (this->__cmp == CmpOperator::EQ)
    return found == true;
  else if (this->__cmp == CmpOperator::NEQ)
    return found == false;
  else
    return false; //XXX throw exception  
}
