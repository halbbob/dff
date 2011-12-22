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
  this->__stop = false;
  this->__fname = fname;
  this->__query = "";
  this->__uid = 0;
  this->__root = NULL;
  this->__ev = new event;
}

Filter::~Filter()
{
  if (this->__root != NULL)
    {
      this->deconnection(this->__root);
      delete this->__root;
    }
}

// Future implementation will provide a filter manager with precompiled
// queries.
// Currently, fname is automatically associated but in future, method will
// ask if it can register the provided name. If name already registered,
// the method will throw an exception to warn the user.
void			Filter::setFilterName(std::string fname) throw (std::string)
{
  this->__fname = fname;
}

std::string		Filter::filterName()
{
  return this->__fname;
}

std::string		Filter::query()
{
  return this->__query;
}

void			Filter::compile(std::string query) throw (std::string)
{
  parserParam		param;
  YY_BUFFER_STATE	state;

  this->__matchednodes.clear();
  if (yylex_init(&param.scanner))
    throw (std::string("error while initializing lexer"));
  if (this->__root != NULL)
    {
      this->deconnection(this->__root);
      delete this->__root;
      this->__root = NULL;
    }
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
  this->connection(this->__root);
  this->__root->compile();
}

void			Filter::processFolder(Node* nodeptr) throw (std::string)
{
  uint64_t		nodescount;
  std::vector<Node*>	children;
  size_t		i;

  this->__reset();
  if (this->__root != NULL)
    {
      if (nodeptr != NULL)
	{
	  if (nodeptr->hasChildren())
	    {
	      nodescount = nodeptr->childCount();
	      this->__notifyNodesToProcess(nodescount);
	      children = nodeptr->children();
	      i = 0;
	      while ((i != children.size()) && (!this->__stop) )
		{
		  if (this->__root->evaluate(children[i]))
		    this->__notifyMatch(children[i]);
		  i++;
		  this->__notifyProgress(i);
		}
	    }
	}
      else
	throw std::string("provided node does not exist");
    }
  else
    throw std::string("no query compiled yet");
  this->__notifyEndOfProcessing(i);
}

void			Filter::process(Node* nodeptr, bool recursive) throw (std::string)
{
  uint64_t		nodescount;
  uint64_t		processed;

  this->__reset();
  processed = 0;
  if (this->__root != NULL)
    {
      if (nodeptr != NULL)
	{
	  if (nodeptr->hasChildren() && recursive)
	    {
	      nodescount = nodeptr->totalChildrenCount();
	      this->__notifyNodesToProcess(nodescount);
	      this->__process(nodeptr, &processed);
	    }
	  else
	    {
	      this->__notifyNodesToProcess(1);
	      if (this->__root->evaluate(nodeptr))
		this->__notifyMatch(nodeptr);
	      this->__notifyProgress(1);
	    }
	}
      else
	throw std::string("provided node does not exist");
    }
  else
    throw std::string("no query compiled yet");
  this->__notifyEndOfProcessing(processed);
}

void				Filter::process(std::list<Node*> nodes) throw (std::string)
{
  uint64_t			processed;
  std::list<Node*>::iterator	it;

  this->__reset();
  processed = 0;
  if (this->__root != NULL)
    {
      if (nodes.size() > 0)
	{
	  this->__notifyNodesToProcess(nodes.size());
	  it = nodes.begin();
	  while (it != nodes.end() && !this->__stop)
	    {
	      if (this->__root->evaluate(*it))
		this->__notifyMatch(*it);
	      this->__notifyProgress(processed++);
	      it++;
	    }
	}
      this->__notifyEndOfProcessing(processed);
    }
  else
    throw std::string("no query compiled yet");
}


void				Filter::process(std::vector<Node*> nodes) throw (std::string)
{
  uint64_t			processed;
  std::vector<Node*>::iterator	it;

  this->__reset();
  processed = 0;
  if (this->__root != NULL)
    {
      if (nodes.size() > 0)
	{
	  this->__notifyNodesToProcess(nodes.size());
	  it = nodes.begin();
	  while (it != nodes.end() && !this->__stop)
	    {
	      if (this->__root->evaluate(*it))
		this->__notifyMatch(*it);
	      this->__notifyProgress(processed++);
	      it++;
	    }
	}
      this->__notifyEndOfProcessing(processed);
    }
  else
    throw std::string("no query compiled yet");
}



void			Filter::__notifyNodesToProcess(uint64_t nodescount)
{
  if (this->__ev != NULL)
    {
      this->__ev->type = Filter::TotalNodesToProcess;
      this->__ev->value = new Variant(nodescount);
      this->notify(this->__ev);
      delete this->__ev->value;
      this->__ev->value = NULL;
    }
}

void			Filter::__notifyMatch(Node* nodeptr)
{
  this->__matchednodes.push_back(nodeptr);
  if (this->__ev != NULL)
    {
      this->__ev->type = Filter::NodeMatched;
      this->__ev->value = new Variant(nodeptr);
      this->notify(this->__ev);
      delete this->__ev->value;
      this->__ev->value = NULL;
    }
}

void			Filter::__notifyProgress(uint64_t processed)
{
  if (this->__ev != NULL)
    {
      this->__ev->value = new Variant(processed);
      this->__ev->type = Filter::ProcessedNodes;
      this->notify(this->__ev);
      delete this->__ev->value;
      this->__ev->value = NULL;
    }
}

void			Filter::__notifyEndOfProcessing(uint64_t processed)
{
  if (this->__ev != NULL)
    {
      this->__ev->type = Filter::EndOfProcessing;
      this->__ev->value = new Variant(processed);
      this->notify(this->__ev);
      delete this->__ev->value;
      this->__ev->value = NULL;
    }
}

void			Filter::__reset()
{
  this->__stop = false;
  this->__matchednodes.clear();
  if (this->__root != NULL && this->__ev != NULL)
    {
      this->__ev->type = Filter::AstReset;
      this->__ev->value = NULL;
      this->__root->Event(this->__ev);
    }
}

void			Filter::__process(Node* nodeptr, uint64_t* processed)
{
  std::vector<Node*>	children;
  uint32_t		i;

  if (nodeptr != NULL && !this->__stop)
    {
      (*processed)++;
      this->__notifyProgress(*processed);
      if (this->__root->evaluate(nodeptr))
	this->__notifyMatch(nodeptr);
      if (nodeptr->hasChildren())
	{
	  children = nodeptr->children();
	  i = 0;
	  while ((i != children.size()) && (!this->__stop))
	    {
	      this->__process(children[i], processed);
	      i++;
	    }
	}
    }
  return;
}

void			Filter::process(uint64_t nodeid, bool recursive) throw (std::string)
{
}

void			Filter::process(uint16_t fsoid, bool recursive) throw (std::string)
{
}

std::vector<Node*>	Filter::matchedNodes()
{
  return this->__matchednodes;
}


void			Filter::Event(event* e)
{
  if (e != NULL && e->type == Filter::StopProcessing)
    {
      this->__stop = true;
      if (this->__root != NULL)
	this->__root->Event(e);
    }
}
