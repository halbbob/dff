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

#include <iostream>

#include <CLucene.h>
#include "../include/vfile.hpp"
#include "../include/index.hpp"
/*
  #include "qanalyzer_p.h"
  #include "qfield_p.h"
  #include "../index/includes/qindexreader_p.h"
*/

//#include "CLucene.h"
/*#include "CLucene/util/Reader.h"
#include "CLucene/util/Misc.h"
#include "CLucene/util/dirent.h" */

Index::Index()
  : __location(""), __writer(NULL), __doc(NULL), __an(NULL), __content(NULL)
{
}

Index::Index(const std::string & location)
  : __writer(NULL), __doc(NULL), __an(NULL)
{
  this->__location = location;
}

Index::~Index()
{
  if (this->__writer)
    delete this->__writer;
  if (__an)
    delete __an;
}

bool	Index::createIndex()
{
  if (this->__location.empty())
    {
      std::cerr << "Query is empty" << std::endl;
      return false;
    }
  lucene::index::IndexWriter *	wr = NULL;
  lucene::analysis::standard::StandardAnalyzer * an
    = new lucene::analysis::standard::StandardAnalyzer;
  //  QString str(this->__location.c_str());
  try
    {
      if (lucene::index::IndexReader::indexExists(this->__location.c_str()))
	{
	  if (lucene::index::IndexReader::isLocked(this->__location.c_str()))
	    lucene::index::IndexReader::unlock(this->__location.c_str());
	  wr = new lucene::index::IndexWriter(this->__location.c_str(), an, false, true);
	}
      else
	wr = new lucene::index::IndexWriter(this->__location.c_str(), an, true, true);
    }
  catch(std::exception & e)
    {
      std::cerr << "Could not instanciate clucene::index::IndexWriter : "
		<< e.what() << std::endl;
      return false;
    }
  wr->setMergeFactor(1000);
  wr->setMinMergeDocs(1000);
  wr->setMaxFieldLength(lucene::index::IndexWriter::DEFAULT_MAX_FIELD_LENGTH);
  this->__writer = wr;
  this->__an = an;
  return true;
}

void	Index::closeIndex()
{
  if (!this->__writer)
    return ;

  try
    {
      this->__writer->optimize();
      this->__writer->close();
      delete this->__writer;
    }
  catch(CLuceneError & e)
    {
      std::cerr << "caught a CLuceneError" << std::endl;
      return ;
    }
  catch(...)
    {
    }
  this->__writer = NULL;
}

bool	Index::indexData(Node * data)
{
  try
    {
      lucene::document::Field * 	content;
      lucene::document::Field * 	path;
      TCHAR *	w_path = (TCHAR *)operator new((data->absolute().size() + 1) * sizeof(w_path));

      STRCPY_AtoT(w_path, data->absolute().c_str(), data->absolute().size());
      w_path[data->absolute().size()] = 0;
      this->__doc = new lucene::document::Document();
      path = new lucene::document::Field(_T("path"), w_path,
		       lucene::document::Field::STORE_YES
		       | lucene::document::Field::INDEX_UNTOKENIZED);
      __indexContent(data, content);
      this->__doc->add(*path);
      this->__doc->add(*__content);
      this->__writer->addDocument((this->__doc), (this->__an));
      //      delete w_path;
      //      delete path;
    }
  catch(std::exception & e)
    {
      std::cout << "Exception caught in Index::indexData() : "
		<< e.what() << std::endl;
      return false;
    }
  catch(...)
    {
      return false;
    }
  return true;
}

void	Index::__indexContent(Node * data, lucene::document::Field * content)
{
  VFile *	vf = NULL;
  char		buf[8193];
  TCHAR		tmp[8193];
  lucene::util::StringBuffer	str;
  unsigned int	nb_read = 0, tot_read = 0;
  TCHAR *	tbuff;

  str.reserve(data->size() + 1);
  vf = data->open();
  while ((nb_read = vf->read(buf, 8192)))
    {
      buf[nb_read] = 0;
      //QByteArray qarr = QByteArray(buf, nb_read);
      STRCPY_AtoT(tmp,buf, nb_read);
      tmp[nb_read] = 0;
      str.append(tmp);
      tot_read += nb_read;
    }
  __content = new lucene::document::Field(_T("contents"), str.getBuffer(),
				lucene::document::Field::STORE_YES
				| lucene::document::Field::INDEX_TOKENIZED);
  vf->close();
}


void	Index::addDocument(lucene::document::Document * doc)
{
  if (!this->__writer || !doc)
    return ;
  this->__writer->addDocument(doc, __an);
  this->__doc = doc;
}

lucene::document::Document *	Index::newDocument()
{

	return NULL;
}

lucene::document::Document *	Index::document() const
{
  return this->__doc;
}

void	Index::setDocument(lucene::document::Document * doc)
{
  this->__doc = doc;
}

const std::string &	Index::location() const
{
  return this->__location;
}

void	Index::setLocation(const std::string & location)
{
  this->__location = location;
}
