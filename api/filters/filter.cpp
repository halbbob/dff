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
  this->__rootast = NULL;
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
  param.expression = NULL;
  state = yy_scan_string(query.c_str(), param.scanner);
  if (yyparse(&param))
    {
      throw (std::string("error while parsing"));
    }
  yy_delete_buffer(state, param.scanner);
  yylex_destroy(param.scanner);
  this->__rootast = param.expression;
}

void	Filter::process(Node* nodeptr, bool recursive) throw (std::string)
{
  Node*	tmp;

  if (this->__rootast != NULL)
    {
      this->__rootast->evaluate(nodeptr, 0);
    }
  else
    throw std::string("no query compiled yet");
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
