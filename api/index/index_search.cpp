/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Romain Bertholon <rbe@digital-forensic.org>
 */

#include <locale>
#include <iostream>
#include <string>
#include <sstream>

#include "../include/vfs.hpp"
#include "../include/vlink.hpp"
#include "../include/index.hpp"

#include <CLucene.h> //queryParser/QueryParser.h>

AttributeIndex::AttributeIndex(std::string name, std::string query) : AttributesHandler(name)
{
  this->__query = query;
}

Attributes 	AttributeIndex::attributes(Node * node)
{
  Attributes	vm;
  Variant * v = new Variant(this->__query);

  vm["query"] = v;
  return vm;
}

IndexSearch::IndexSearch() : __location(".")
{
}

IndexSearch::IndexSearch(const std::string & location)
{
  this->__location = location;
}

IndexSearch::~IndexSearch()
{
}

void	IndexSearch::exec_query(const std::string & query,
				const std::string & must_contain_query)
{

  lucene::analysis::standard::StandardAnalyzer * an = NULL;
  lucene::search::IndexSearcher * index = NULL;

  if (this->__location.empty())
    return ;
  if (query.empty() && must_contain_query.empty())
    return ;
  this->__query = query;
  this->__must = must_contain_query;

  try
    {
      an = _CLNEW lucene::analysis::standard::StandardAnalyzer;
      index = _CLNEW lucene::search::IndexSearcher(this->__location.c_str());
    }
  catch(std::exception & e)
    {
      std::cerr << "Cannot perfrorm search : " << e.what()
		<< "Does the index exist ?"
		<< std::endl;
      _CLDELETE(index);
      _CLDELETE(an);
      return ;
    }

  lucene::search::Query * q;
  TCHAR qq[512];

  STRCPY_AtoT(qq, query.c_str(), 512);
  qq[query.size() >= 512 ? 512 : query.size()];
  if (must_contain_query.empty())
    q = lucene::queryParser::QueryParser::parse(qq, _T("contents"), an);
  else
    q = __getMultiSearchQuery(must_contain_query, an);

  // if the query is not NULL and the Hits * is not NULL create VLinks and then
  // free resources before exiting.
  if (!q)
    std::cerr << "An error occured while parsing the query. Cannot proceed."
	      << std::endl;
  else
    {
      // Get hits and display results if not NULL.
      lucene::search::Hits *  h = index->search(q);
      if (!h)
	std::cerr << "An error eccured while fetching results. Cannot proceed."
		  << std::endl;
      else
	{
	  __displayResults(h);
	  _CLDELETE(h);
	}
      _CLDELETE(q);
    }
  _CLDELETE(index);
  _CLDELETE(an);
}

void	IndexSearch::__displayResults(lucene::search::Hits * h)
{
  VFS &	vfs = VFS::Get();
  Node * root = vfs.root;
  Node * query = this->__newIndexation(root);

  std::cout << "Found " << h->length() << " hits." << std::endl;

  // Browse all hits.
  for (int32_t i = 0 ; i < h->length(); i++)
    {
      std::string	node_name;
      lucene::document::Document & doc = h->doc(i);
      Node *		node = NULL;

      node_name = narrow(doc.get(_T("path")));
      node = vfs.GetNode(node_name);
      if (node == NULL)
	std::cerr << "Node '" << node_name << "' does not exist." << std::endl;
      else
	VLink * l = new VLink(node, query, node->name());
    }

  // to refresh the gui, otherwise results never appear in the VFS.
  event * e = new event();
  e->value = new Variant(query);
  VFS::Get().notify(e);
}

Node *	IndexSearch::__newIndexation(Node * root)
{
  Node * query = NULL;
  Node * tmp = NULL;
  VFS &	vfs = VFS::Get();
  std::string	node_name;

  // instanciate a AttributeHandler
  AttributeIndex * attr = new AttributeIndex("index", this->__query);

  // add the query as an attribute and register it
  if (this->__query.size() > 10)
    node_name = "Results::" + this->__query.substr(0, 10) + "...";
  else
    node_name = "Results::" + this->__query;
  query = new Node(node_name);
  query->registerAttributes(attr);

  // add results in node "Searched items"
  tmp = vfs.GetNode("/Searched items");
  if (!tmp)
    return NULL;
  tmp->addChild(query);
  return query;
}

lucene::search::Query * IndexSearch::__getMultiSearchQuery(const std::string & query,
						   lucene::analysis::standard::StandardAnalyzer * an)
{
  /*
    # TODO : research onmultiple keywords. By default clucene perform a logical OR
    between the different terms of the search. The logical AND should be added.
  */
  return NULL;
}

char* IndexSearch::narrow( const wstring& str )
{
  ostringstream stm ;
  const ctype<char>& ctfacet =
    use_facet< ctype<char> >( stm.getloc() ) ;
  for( size_t i=0 ; i<str.size() ; ++i )
    stm << ctfacet.narrow( str[i], 0 ) ;
  string st = stm.str();
  char* c = new char [st.size()+1];
  strcpy(c, st.c_str());
  return c;
}
