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

//#include <QString>
//#include <QtDebug>

#include "../include/vfs.hpp"
//#include "../include/node.hpp"
//#include "../include/eventhandler.hpp"
#include "../include/vlink.hpp"
#include "../include/index.hpp"

#include <CLucene/queryParser/QueryParser.h>

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

IndexSearch::IndexSearch()
  : __index(NULL), __location(".")
{
}

IndexSearch::IndexSearch(const std::string & location)
  : __index(NULL)
{
  this->__location = location;
}

IndexSearch::~IndexSearch()
{
  if (__index)
    delete __index;
}


void	IndexSearch::exec_query(const std::string & query,
				const std::string & must_contain_query)
{
  if (this->__location.empty())
    return ;
  if (query.empty() && must_contain_query.empty())
    return ;
  this->__query = query;
  this->__must = must_contain_query;
  lucene::analysis::standard::StandardAnalyzer * an 
    = new lucene::analysis::standard::StandardAnalyzer;
  lucene::search::IndexSearcher *	index = NULL;

  try
    {
      index = new lucene::search::IndexSearcher(this->__location.c_str());
    }
  catch(...)
    {
      std::cerr << "Cannot perfrorm search : IOException caught."
		<< "Does the index exists ?"
		<< std::endl;
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
  if (!q)
    std::cerr << "An error occured while parsing the query." << std::endl;
  else
    {
      lucene::search::Hits *  h = index->search(q);
      if (!h)
	{
	  std::cerr << "cannot get hits" << std::endl;
	}
      else
	{
	  __displayResults(h);
	  // _CLDELETE(h);
	}
      //      _CLDELETE(q);
    }
}

void	IndexSearch::__displayResults(lucene::search::Hits * h)
{
  VFS &	vfs = VFS::Get();
  Node * root = vfs.root;
  Node * query = this->__newIndexation(root);

  std::cout << "found " << h->length() << " hits." << std::endl;
  for (int32_t i = 0 ; i < h->length(); i++)
    {
      std::string	node_name;
      lucene::document::Document & doc = h->doc(i);
      Node *		node = NULL;

      node_name = narrow(doc.get(_T("path")));
      node = vfs.GetNode(node_name);
      if (node == NULL)
	{
	  std::cerr << "Node '" << node_name << "' does not exist." << std::endl;
	}
      else
	VLink * l = new VLink(node, query, node->name());
    }

  // to refresh the gui
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
  AttributeIndex * attr = new AttributeIndex("index", this->__query);

  if (this->__query.size() > 10)
    node_name = "Results::" + this->__query.substr(0, 10) + "...";
  else
    node_name = "Results::" + this->__query;

  query = new Node(node_name);
  query->registerAttributes(attr);

  //  might need revert
  tmp = vfs.GetNode("/Searched items");
  if (!tmp)
    return NULL;
  tmp->addChild(query);
  return query;
  return NULL;
}

lucene::search::Query * IndexSearch::__getMultiSearchQuery(const std::string & query,
						   lucene::analysis::standard::StandardAnalyzer * an)
{
  /*  QString	str(query.c_str());
  QStringList	fields  = str.split(" ");
  QCLuceneBooleanQuery * bo_q = new QCLuceneBooleanQuery;

  for (int i = 0; i < fields.size(); ++i)
    {
      QCLuceneQuery * q = QCLuceneQueryParser::parse(fields.at(i), "contents", *an);
      if (!q)
	continue ;
      bo_q->add(q, true, false);
    }  
  if (!this->__query.empty())
    {
      QCLuceneQuery * q2
	= QCLuceneQueryParser::parse(QString(this->__query.c_str()),
				     "contents", *an);
      if (!q2)
	return bo_q;
      bo_q->add(q2, false, false);
    }
    return bo_q; */
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
