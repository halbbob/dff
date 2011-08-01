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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include "filter.hpp"
#include "parserparam.hpp"
#include "parser.hpp"
#include "lexer.hpp"
#include <iostream>

int yyparse(void *param);

Filter::Filter(std::string fname)
{
  this->__fname = fname;
  this->__query = "";
  this->__uid = 0;
  this->__root = NULL;
}

Filter::~Filter()
{
}

// Future implementation will provide a filter manager with precompiled
// queries.
// Currently, fname is automatically associated but in future, method will
// ask if it can register the provided name. If name already registered,
// the method will throw an exception to warn the user.
void		Filter::setFilterName(std::string fname) throw (std::string)
{
  this->__fname = fname;
}

std::string	Filter::filterName()
{
  return this->__fname;
}

std::string	Filter::query()
{
  return this->__query;
}

void	Filter::compile(std::string query) throw (std::string)
{
  parserParam		param;
  YY_BUFFER_STATE	state;

  if (yylex_init(&param.scanner))
    throw (std::string("error while initializing lexer"));
  param.root = NULL;
  state = yy_scan_string(query.c_str(), param.scanner);
  if (yyparse(&param))
    {
      throw (std::string("error while parsing"));
    }
  this->__query = query;
  yy_delete_buffer(state, param.scanner);
  yylex_destroy(param.scanner);
  this->__root = param.root;
  this->__root->compile();
}

void		Filter::process(Node* nodeptr, bool recursive) throw (std::string)
{
  uint64_t	nodescount;
  uint64_t	processed;
  event*	e;
  
  if (this->__root != NULL)
    {
      if (nodeptr != NULL)
	{
	  processed = 0;
	  e = new event;
	  e->type = 0x200;
	  if (nodeptr->hasChildren() && recursive)
	    {
	      nodescount = nodeptr->totalChildrenCount();
	      e->value = new Variant(nodescount);
	      this->notify(e);
	      delete e->value;
	      this->__process(nodeptr, &processed, e);
	    }
	  else
	    {
	      e->value = new Variant(1);
	      e->type = 0x200;
	      this->notify(e);
	      delete e->value;
	      if (this->__root->evaluate(nodeptr))
		{
		  e->type = 0x202;
		  e->value = new Variant(nodeptr);
		  this->notify(e);
		}
	      e->value = new Variant(1);
	      e->type = 0x201;
	      this->notify(e);
	      delete e->value;
	    }
	  delete e;
	}
      else
	throw std::string("provided node does not exist");
    }
  else
    throw std::string("no query compiled yet");
}

void			Filter::__process(Node* nodeptr, uint64_t* processed, event* e)
{
  std::vector<Node*>	children;
  uint32_t		i;

  if (nodeptr != NULL)
    {
      (*processed)++;
      e->type = 0x201;
      e->value = new Variant(*processed);
      this->notify(e);
      delete e->value;
      if (this->__root->evaluate(nodeptr))
	{
	  e->type = 0x202;
       	  e->value = new Variant(nodeptr);
	  this->notify(e);
	  delete e->value;
       	}
      if (nodeptr->hasChildren())
	{
	  children = nodeptr->children();
	  for (i = 0; i != children.size(); i++)
	    this->__process(children[i], processed, e);
	}
    }
  return;
}

void	Filter::process(uint64_t nodeid, bool recursive) throw (std::string)
{
}

void	Filter::process(uint16_t fsoid, bool recursive) throw (std::string)
{
}

void	Filter::Event(event* e)
{
}
