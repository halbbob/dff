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
 *  Frederic Bagueline. <fba@digital-forensic.org>
 */

#include "attributesindexer.hpp"
#ifndef WIN32
#include <pthread.h>
#endif

#ifndef WIN32
pthread_mutex_t attrsmutex = PTHREAD_MUTEX_INITIALIZER;
#endif

AttributesIndexer&	AttributesIndexer::Get()
{
  static AttributesIndexer single;
  return single;
}

AttributesIndexer::AttributesIndexer()
{
  //VFS::Get().connection(this);
}

AttributesIndexer::~AttributesIndexer()
{
}

void	AttributesIndexer::__mapAttrNamesAndTypes(Node* node, std::map<std::string, uint8_t>* attrsmapping)
{
  std::vector<Node*>				children;
  std::map<std::string, uint8_t>*		attrsnamestypes;
  std::map<std::string, uint8_t>::iterator	mit;
  int						i;

  attrsnamestypes = node->attributesNamesAndTypes();
  for (mit = attrsnamestypes->begin(); mit != attrsnamestypes->end(); mit++)
    attrsmapping->insert(pair<std::string, uint8_t>(mit->first, mit->second));
  delete attrsnamestypes;
  if (node->hasChildren())
    {
      children = node->children();
      int size;
      int i;
      size = children.size();
      for (i = 0; i != size; i++)
	this->__mapAttrNamesAndTypes(children[i], attrsmapping);
    }
}


void	AttributesIndexer::registerAttributes(Node *n)
{
  std::map<std::string, uint8_t>*	attrsmapping;
  std::map<std::string, uint8_t>::iterator	mit;
  /*
  if (n != NULL)
    {
      attrsmapping = new   std::map<std::string, uint8_t>;
      this->__mapAttrNamesAndTypes(n, attrsmapping);
      pthread_mutex_lock(&attrsmutex);
      for (mit = attrsmapping->begin(); mit != attrsmapping->end(); mit++)
	this->__attrNamesAndTypes[mit->first] = mit->second;
      pthread_mutex_unlock(&attrsmutex);
      } */
}


void	AttributesIndexer::Event(event* e)
{
  Node*		node;

  if ((e->value != NULL) && (e->value->type() == typeId::Node))
    {
      node = e->value->value<Node*>();
      this->registerAttributes(node);
    }
}

std::map<std::string, uint8_t>	AttributesIndexer::attrNamesAndTypes()
{
  return this->__attrNamesAndTypes;
}
