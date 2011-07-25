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
  yy_delete_buffer(state, param.scanner);
  yylex_destroy(param.scanner);
  this->__root = param.root;
  this->__root->compile();
}

void	Filter::process(Node* nodeptr, bool recursive) throw (std::string)
{
  //event*		e;
  std::vector<Node*>	children;
  int			i;

  if ((this->__root != NULL) && (nodeptr != NULL))
    {
      if (this->__root->evaluate(nodeptr, 0))
	{
	  std::cout << "NODE MATCHED ---> " << nodeptr->absolute() << std::endl;
	  // e = new event;
       	  // e->type = event::OTHER;
       	  // e->value = new Variant(nodeptr);
       	  // this->notify(e);
       	}
      if (nodeptr->hasChildren() && recursive)
	{
	  children = nodeptr->children();
	  for (i = 0; i != children.size(); i++)
	    {
	      //std::cout << children[i] << std::endl;
	      this->process(children[i], recursive);
	    }
	}
    }
  else
    throw std::string("no query compiled yet");
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
