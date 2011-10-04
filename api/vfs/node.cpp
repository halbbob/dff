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
 *  Solal J. <sja@digital-forensic.org>
 */

#include "node.hpp"
#include "attributesindexer.hpp"

Node::Node()
{
}

Node::Node(std::string name, uint64_t size, Node* parent, fso* fsobj)
{
  this->__common_attributes = 0;
  this->__childcount = 0;
  this->__at = 0;
  //this->__checkState = 0;
  this->__fsobj = fsobj;
  this->__size = size;
  this->__parent = parent;
  if (this->__fsobj != NULL)
    this->__uid = this->__fsobj->registerNode(this);
  else if (parent != NULL)
    this->__uid = VFS::Get().registerOrphanedNode(this);
  else
    this->__uid = 0;
  if (this->__parent != NULL)
    this->__parent->addChild(this);
  this->__name = name;
}

Node::~Node()
{
  if (!this->__children.empty())
    this->__children.clear();
}

void		Node::setFile()
{
  if (!this->isDir())
    this->__common_attributes |= ISFILE;
  else
    throw("attribute ISDIR already setted");
}

void		Node::setDir()
{
  if (!this->isFile())
    this->__common_attributes |= ISDIR;
  else
    throw("attribute ISFILE already setted");
}

void		Node::setLink()
{
  this->__common_attributes |= ISLINK;
}

void		Node::setDeleted()
{
  this->__common_attributes |= ISDELETED;
}

void		Node::setSize(uint64_t size)
{
  this->__size = size;
}

void	Node::setFsobj(fso *obj)
{
  this->__fsobj = obj;
}

void		Node::setParent(Node *parent)
{
  if (parent != NULL)
    {
      this->__parent = parent;
      //this->__parent->addChild(this);
    }
  else
    ;//XXX throw() NodeException;
}

void   Node::fileMapping(FileMapping *)
{
}

uint64_t	Node::uid()
{
  return this->__uid;
}

Attributes	Node::_attributes(void)
{
  Attributes attr;

  return (attr);
}


void 	Node::attributesByTypeFromVariant(Variant* variant, uint8_t type, Attributes* result)
{
  Variant*	vptr;

  if (!(variant))
    return ;
  if (variant->type() == typeId::List)
    {
      std::list<Variant*> lvariant = variant->value<std::list< Variant*> >();
      std::list<Variant*>::iterator it = lvariant.begin();
      for (; it != lvariant.end(); it++)
	this->attributesByTypeFromVariant((*it), type, result); 
    }
  else if (variant->type() == typeId::Map)
    {
      Attributes mvariant = variant->value<Attributes >();
      Attributes::iterator it = mvariant.begin();
      for (; it != mvariant.end(); it++)
	{
	  if (it->second->type() == type)
	    {
	      if (result->find(it->first) == result->end())
		{
		  vptr = new Variant(it->second);
		  result->insert(std::pair<std::string, Variant*>(it->first, vptr));
		}
	      else
		;//XXX, we have to find a way to manage same attributes naming at different level. At the moment, this condition is to avoid memleak
	    }
	  else
	    this->attributesByTypeFromVariant(it->second, type, result);
	}
    }
}

void 	Node::attributesByTypeFromVariant(Variant* variant, uint8_t type, Attributes* result, std::string current)
{
  if (!(variant))
    return ;
  if (variant->type() == typeId::List)
    {
      std::list<Variant*> lvariant = variant->value<std::list< Variant*> >();
      std::list<Variant*>::iterator it = lvariant.begin();
      for (; it != lvariant.end(); it++)
	this->attributesByTypeFromVariant((*it), type, result, current);
    }
  else if (variant->type() == typeId::Map)
    {
      Attributes mvariant = variant->value<Attributes >();
      Attributes::iterator it = mvariant.begin();
      std::string	abs;
      for (; it != mvariant.end(); it++)
	{
	  if (current.empty())
	    abs = (*it).first;
	  else
	    abs = current + '.' + (*it).first;
	  if (it->second->type() == type)
	    result->insert(std::pair<std::string, Variant*>(abs, new Variant(it->second)));
	  else
	    this->attributesByTypeFromVariant(it->second, type, result, abs);
	}
    }
}

void	Node::attributesByNameFromVariant(Variant* variant, std::string name, std::list<Variant*>* result)
{
  if (!(variant))
    return ;
  if (variant->type() == typeId::List)
    {
      std::list<Variant*> lvariant = variant->value<std::list< Variant*> >();
      std::list<Variant*>::iterator it = lvariant.begin();
      for (; it != lvariant.end(); it++)
	this->attributesByNameFromVariant((*it), name, result);
    }
  else if (variant->type() == typeId::Map)
    {
      Attributes mvariant = variant->value<Attributes >();
      Attributes::iterator it = mvariant.begin();
      for (; it != mvariant.end(); it++)
	{
	  if (it->first == name)
	    result->push_back(new Variant(it->second));
	  else
	    this->attributesByNameFromVariant(it->second, name, result);
	}
    }
}


void	Node::attributesNamesAndTypesFromVariant(Variant* variant, std::map<std::string, uint8_t> *namestypes, std::string current)
{
  if (!(variant))
    return ;
  if (variant->type() == typeId::List)
    {
      std::list<Variant*> lvariant = variant->value<std::list< Variant*> >();
      std::list<Variant*>::iterator it = lvariant.begin();
      for (; it != lvariant.end(); it++)
	this->attributesNamesAndTypesFromVariant((*it), namestypes, current);
    }
  else if (variant->type() == typeId::Map)
    {
      Attributes mvariant = variant->value<Attributes >();
      Attributes::iterator it = mvariant.begin();
      std::string	abs;
      for (; it != mvariant.end(); it++)
	{
	  if (current.empty())
	    abs = it->first;
	  else
	    abs = current + '.' + it->first;
	  namestypes->insert(std::pair<std::string, uint8_t>(abs, it->second->type()));
	  this->attributesNamesAndTypesFromVariant(it->second, namestypes, abs);
	}
    }  
}

void	Node::attributesNamesFromVariant(Variant* variant, std::list<std::string > *names)
{
  if (!(variant))
    return ;
  if (variant->type() == typeId::List)
    {
      std::list<Variant*> lvariant = variant->value<std::list< Variant*> >();
      std::list<Variant*>::iterator it = lvariant.begin();
      for (; it != lvariant.end(); it++)
	this->attributesNamesFromVariant((*it), names); 
    }
  else if (variant->type() == typeId::Map)
    {
      Attributes mvariant = variant->value<Attributes >();
      Attributes::iterator it = mvariant.begin();
      for (; it != mvariant.end(); it++)
	{
	  names->push_back(it->first);
	  this->attributesNamesFromVariant(it->second, names);
	}
    }
}

void	Node::attributesNamesFromVariant(Variant* variant, std::list<std::string > *names, std::string current)
{
  if (!(variant))
    return ;
  if (variant->type() == typeId::List)
    {
      std::list<Variant*> lvariant = variant->value<std::list< Variant*> >();
      std::list<Variant*>::iterator it = lvariant.begin();
      for (; it != lvariant.end(); it++)
	this->attributesNamesFromVariant((*it), names, current);
    }
  else if (variant->type() == typeId::Map)
    {
      Attributes mvariant = variant->value<Attributes >();
      Attributes::iterator it = mvariant.begin();
      std::string	abs;
      for (; it != mvariant.end(); it++)
	{
	  if (current.empty())
	    abs = it->first;
	  else
	    abs = current + '.' + it->first;
	  names->push_back(abs);
	  this->attributesNamesFromVariant(it->second, names, abs);
	}
    }
}


std::list<std::string>*  	Node::attributesNames(attributeNameType tname)
{
  std::list<std::string>*	result;
  Attributes*			attr;
  Attributes::iterator		attrit;

  attr = NULL;
  result = NULL;
  if ((result = new std::list<std::string>) != NULL)
    {
      if ((attr = this->attributes()) != NULL)
	{
	  for (attrit = attr->begin(); attrit != attr->end(); attrit++)
	    {
	      result->push_back(attrit->first);
	      if (tname == ABSOLUTE_ATTR_NAME)
		this->attributesNamesFromVariant(attrit->second, result, attrit->first);
	      else
		this->attributesNamesFromVariant(attrit->second, result);
	      delete attrit->second;
	    }
	  delete attr;
	}
    }
  return (result);
}

Variant*		Node::attributeByAbsoluteNameFromVariant(Variant* variant, std::string name)
{
  std::string	subname;
  std::string	subabs;
  size_t	idx;

  idx = name.find(".");
  if (idx != std::string::npos)
    {
      subname = name.substr(0, idx);
      subabs = name.substr(idx+1, name.size());
    }
  else
    {
      subname = name;
      subabs = "";
    }
  if (!(variant))
    return NULL;
  if ((variant->type() == typeId::List) && (!subabs.empty()))
    {
      std::list<Variant*> lvariant = variant->value<std::list< Variant*> >();
      std::list<Variant*>::iterator it = lvariant.begin();
      Variant*	res = NULL;
      while (it != lvariant.end() && res == NULL)
	res = this->attributeByAbsoluteNameFromVariant((*it), subabs);
      return res;
    }
  else if (variant->type() == typeId::Map)
    {
      Attributes mvariant = variant->value<Attributes >();
      Attributes::iterator it;
      
      it = mvariant.find(subname);
      if (it != mvariant.end())
	{
	  if (!subabs.empty())
	    return this->attributeByAbsoluteNameFromVariant(it->second, subabs);
	  else
	    return new Variant(it->second);
	}
      else
	return NULL;
    }
  else
    return NULL;
}

Variant*			Node::attributesByName(std::string name, attributeNameType tname)
{
  Attributes*			attr;
  Variant*			result;
  std::list<Variant*>*		vlist;
  Attributes::iterator		attrit;
  Variant*			vptr;
  
  result = NULL;
  attr = NULL;
  vlist = NULL;
  vptr = NULL;
  if ((attr = this->attributes()) != NULL)
    {
      if (tname == ABSOLUTE_ATTR_NAME)
	{
	  std::string	subname;
	  std::string	subabs;
	  size_t	idx;

	  idx = name.find(".");
	  if (idx != std::string::npos)
	    {
	      subname = name.substr(0, idx);
	      subabs = name.substr(idx+1, name.size());
	      for (attrit = attr->begin(); attrit != attr->end(); attrit++)
		{
		  if (attrit->first == subname)
		    result = this->attributeByAbsoluteNameFromVariant(attrit->second, subabs);
		  delete attrit->second;
		}
	    }
	  else
	    {
	      for (attrit = attr->begin(); attrit != attr->end(); attrit++)
		{
		  if (attrit->first == name)
		    result = new Variant(attrit->second);
		  delete attrit->second;
		}
	    }
	}
      else
	{
	  vlist = new std::list<Variant*>;
	  for (attrit = attr->begin(); attrit != attr->end(); attrit++)
	    {
	      if (attrit->first == name)
		if ((vptr = new Variant(attrit->second)) != NULL)
		  vlist->push_back(vptr);
	      this->attributesByNameFromVariant(attrit->second, name, vlist);
	      delete attrit->second;
	    }
	  if (vlist->size())
	    result = new Variant(*vlist);
	  delete vlist;
	}
      delete attr;
    }
  return result;
}


Attributes*			Node::attributesByType(uint8_t type, attributeNameType tname)
{
  Attributes*			attr;
  Attributes*			result;
  Attributes::iterator		attrit;
  Variant*			vptr;
  
  result = NULL;
  attr = NULL;
  if ((result = new Attributes) != NULL)
    {
      if ((attr = this->attributes()) != NULL)
	{
	  for (attrit = attr->begin(); attrit != attr->end(); attrit++)
	    {
	      vptr = new Variant(attrit->second);
	      result->insert(std::pair<std::string, Variant*>(attrit->first, vptr));
	      if (tname == ABSOLUTE_ATTR_NAME)
		this->attributesByTypeFromVariant(attrit->second, type, result, attrit->first);
	      else
		this->attributesByTypeFromVariant(attrit->second, type, result);
	      delete attrit->second;
	    }
	  delete attr;
	}
    }
  return result;
}


std::map<std::string, uint8_t>*	Node::attributesNamesAndTypes()
{
  std::map<std::string, uint8_t>*	result;
  Attributes*				attr;
  Attributes::iterator			attrit;
  
  result = NULL;
  attr = NULL;
  if ((result = new std::map<std::string, uint8_t>) != NULL)
    {
      if ((attr = this->attributes()) != NULL)
	{
	  for (attrit = attr->begin(); attrit != attr->end(); attrit++)
	    {
	      if (attrit->second != NULL)
		{
		  result->insert(std::pair<std::string, uint8_t>(attrit->first, attrit->second->type()));
		  this->attributesNamesAndTypesFromVariant(attrit->second, result, attrit->first);
		  delete attrit->second;
		}
	    }
	  delete attr;
	}
    }
  return result;
}


Attributes*			Node::attributes()
{
  Attributes* attr;
  std::set<AttributesHandler*>::iterator handler;
  Variant*	vptr = NULL;
  Attributes	nodeAttributes;


  attr = NULL;
  if ((attr = new std::map<std::string, Variant*>) != NULL)
    {
      if ((vptr = this->dataType()) != NULL)
        attr->insert(std::pair<std::string, Variant*>(std::string("type"), vptr));

      if (this->__fsobj != NULL)
	{
	  nodeAttributes = this->_attributes();
	  if (!nodeAttributes.empty())
	    {
	      if ((vptr = new Variant(nodeAttributes)) != NULL)
	       	attr->insert(std::pair<std::string, Variant*>(this->__fsobj->name, vptr));
	    }
	}
      for (handler = this->__attributesHandlers.begin(); handler != this->__attributesHandlers.end(); handler++)
        {
          if ((vptr = new Variant((*handler)->attributes(this))) != NULL)
      	    attr->insert(std::pair<std::string, Variant*>((*handler)->name(), vptr));
        }
    }
  return attr;
}

Attributes		Node::fsoAttributes()
{
  return this->_attributes();
}

Attributes*		Node::dynamicAttributes()
{
  Attributes* attr = new std::map<std::string, Variant*>;


  std::set<AttributesHandler*>::iterator handler;
  for (handler = this->__attributesHandlers.begin(); handler != this->__attributesHandlers.end(); handler++)
  {
    (*attr)[(*handler)->name()] = new Variant((*handler)->attributes(this));	
  } 	

  return attr;
}

Variant*	Node::dynamicAttributes(std::string name)
{
  std::set<AttributesHandler* >::iterator handler;

  for (handler = this->__attributesHandlers.begin(); handler != this->__attributesHandlers.end(); handler++)
  {
    if ((*handler)->name() == name)
     return new Variant((*handler)->attributes(this));	
  } 	

  return (new Variant());
}

std::list<std::string>*		Node::dynamicAttributesNames(void)
{
  std::set<AttributesHandler* >::iterator handler;
  std::list<std::string>*	names = new std::list<std::string>;

  for (handler = this->__attributesHandlers.begin(); handler != this->__attributesHandlers.end(); handler++)
     names->push_back((*handler)->name());

  return (names);
}

AttributesHandler::AttributesHandler(std::string handlerName)
{
  this->__handlerName = handlerName;
}

std::string AttributesHandler::name(void)
{
  return (this->__handlerName);
}


AttributesHandler::~AttributesHandler()
{
}

bool			Node::registerAttributes(AttributesHandler* ah)
{
  bool	ret;
  
  ret = this->__attributesHandlers.insert(ah).second;
  //AttributesIndexer::Get().registerAttributes(this);
  return ret;
}

uint64_t	Node::size()
{
  return this->__size;
}

std::string	Node::path()
{
  std::string path;
  Node	*tmp;

  if (this->__parent == this)
    return "";
  path = "";
  tmp = this->__parent;
  if (!tmp)
    {
      path = "";
      return path;
    }
  while ((tmp->__parent != tmp) && (tmp->__parent != NULL))
    {
      path = tmp->name() + "/" + path;
      tmp = tmp->parent();
    }
  if (tmp->__parent == tmp)
    path = "/" + path;
  return path;
}

std::string	Node::name()
{
  return this->__name;
}

std::string	Node::absolute()
{
  return this->path() + this->__name;
}

std::string	Node::extension()
{
  size_t	dpos;
  std::string	ext;
  
  if ((dpos = this->__name.rfind(".")) != std::string::npos)
    ext = this->__name.substr(dpos+1);
  return ext;
}

bool				Node::isFile()
{
  if ((this->__common_attributes & ISFILE) == ISFILE)
    return true;
  else
    return false;
}

bool				Node::isDir()
{
  if ((this->__common_attributes & ISDIR) == ISDIR)
    return true;
  else
    return false;
}

bool				Node::isLink()
{
  if ((this->__common_attributes & ISLINK) == ISLINK)
    return true;
  else
    return false;
}

bool				Node::isVDir()
{
  if (this->isFile() && this->hasChildren())
    return true;
  else
    return false;
}

bool				Node::isDeleted()
{
  if ((this->__common_attributes & ISDELETED) == ISDELETED)
    return true;
  else
    return false;
}


fso*		Node::fsobj()
{
  return this->__fsobj;
}

Node*		Node::parent()
{
  return this->__parent;
}

std::vector<class Node*>	Node::children()
{
  return this->__children;
}

bool		Node::addChild(class Node *child)
{
  child->setParent(this);
  child->__at = this->__childcount; 
  this->__children.push_back(child);
  this->__childcount++;
  return true;
}

bool            Node::hasChildren()
{
  if (this->__childcount > 0)
    return true;
  else
    return false;
}

uint32_t	Node::childCount()
{
  return this->__childcount;
}

uint64_t	Node::totalChildrenCount(uint32_t depth)
{
  uint64_t	totalsub;
  size_t	i;

  totalsub = this->__childcount;
  if (depth != 0)
    {
      for (i = 0; i != this->__children.size(); i++)
	if (this->__children[i]->hasChildren())
	  totalsub += this->__children[i]->totalChildrenCount(depth-1);
    }
  return totalsub;
}

uint32_t	Node::at()
{
  return this->__at;	
}

VFile*		Node::open()
{
  int32_t	fd;
  VFile		*temp;

  if (this->__fsobj == NULL)
    throw vfsError("Can't Open file");
  try
    {
      if ((fd = this->__fsobj->vopen(this)) >= 0)
	{
	  temp = new VFile(fd, this->__fsobj, this);
	  return (temp);
	}
      throw vfsError("Can't Open file");
    }
  catch (vfsError e)
    {
      throw vfsError("Node::open(void) throw\n" + e.error);
    }
}


void	 	Node::setId(uint32_t id)
{
  this->__id = id;
}

uint32_t	Node::id()
{
  return this->__id;
}

string Node::icon(void)
{
  if (!(this->hasChildren()))
  {
    if (this->isDir())
      return (":folder_128.png");
    if (!(this->size()))
      return (":folder_empty_128.png");
    return (":folder_empty_128.png");
  }
  else
  {
    if (this->size() != 0)
      return (":folder_documents_128.png");
    else
      return (":folder_128.png");
  }
}

Variant*	Node::dataType(void) 
{
  Variant*	types = NULL;

  class DataTypeManager*	typeDB = DataTypeManager::Get();
  types = typeDB->type(this);
  return types;
}


void		Node::__compatibleModulesByType(const std::map<std::string, Constant*>& cmime, Attributes& dtypes, std::list<std::string>* result)
{
  std::map<std::string, Constant*>::const_iterator	cit;
  list<Variant*>					lvalues;
  list<Variant*>::iterator				lit;
  Attributes::iterator					dit;
  bool							match;

  for (cit = cmime.begin(); cit != cmime.end(); cit++)
    {
      match = false;
      if ((cit->second != NULL) && (cit->second->type() == typeId::String))
  	{
  	  lvalues = cit->second->values();
	  lit = lvalues.begin();
  	  while (lit != lvalues.end() && !match)
  	    {
	      dit = dtypes.begin();
  	      while (dit != dtypes.end() && !match)
  		{
  		  std::string	cval = (*lit)->value<std::string>();
  		  if ((dit->second != NULL) && (dit->second->type() == typeId::String)
  		      && (dit->second->value<std::string>().find(cval) != std::string::npos))
  		    {
  		      match = true;
  		      result->push_back(cit->first);
  		    }
  		  dit++;
  		}
  	      lit++;
  	    }
  	}
    }
}


void		Node::__compatibleModulesByExtension(const std::map<std::string, Constant*>& cextensions, std::string& ext, std::list<std::string>* result)
{
  std::map<std::string, Constant*>::const_iterator	cit;
  list<Variant*>					lvalues;
  list<Variant*>::iterator				lit;

  for (cit = cextensions.begin(); cit != cextensions.end(); cit++)
    {
      if ((cit->second != NULL) && (cit->second->type() == typeId::String))
	{
	  lvalues = cit->second->values();
	  for (lit = lvalues.begin(); lit != lvalues.end(); lit++)
	    if (ext == (*lit)->value<std::string>())
	      result->push_back(cit->first);
	}
    }
}

std::list<std::string>*		Node::compatibleModules(void)
{
  list<std::string>*			result;
  Variant*				dtypesptr;
  Attributes				dtypes;
  ConfigManager*			cm;
  std::map<std::string, Constant*>	constants;
  std::string				ext;

  result = NULL;
  if ((cm = ConfigManager::Get()) != NULL)
    {
      result = new list<std::string>;
      constants = cm->constantsByName("mime-type");
      if (!constants.empty() && ((dtypesptr = this->dataType()) != NULL))
	{
	  dtypes = dtypesptr->value<Attributes >();
	  if (!dtypes.empty())
	    this->__compatibleModulesByType(constants, dtypes, result);
	  delete dtypesptr;
	}
      ext = this->extension();
      if (!ext.empty())
	{
	  constants = cm->constantsByName("extension-type");
	  if (!constants.empty())
	    this->__compatibleModulesByExtension(constants, ext, result);
	}
    }
  return result;
}

bool	Node::isCompatibleModule(string modname)
{
  
  ConfigManager*		cm;
  Config*			conf;
  Constant*			constant;
  std::list<Variant*>		values;
  std::list<Variant*>::iterator	it;
  bool				compat;
  
  compat = false;
  if (((cm = ConfigManager::Get()) != NULL) && ((conf = cm->configByName(modname)) != NULL))
    {
      Attributes	dtypes;
      Variant*		vptr;
      std::string	ext;

      vptr = this->dataType();
      ext = this->extension();
      if (vptr != NULL && ((constant = conf->constantByName("mime-type")) != NULL))
	{
	  dtypes = vptr->value<Attributes >();
	  values = constant->values();
	  for (Attributes::iterator mit = dtypes.begin(); mit != dtypes.end(); mit++)
	    {
	      if (mit->second->type() == typeId::String)
		{
		  std::string	dtype = mit->second->value<std::string>();
		  it = values.begin();
		  while (it != values.end() && !compat)
		    {
		      if ((*it)->type() == typeId::String && dtype.find((*it)->value<std::string>()) != std::string::npos)
			compat = true;
		      it++;
		    }
		}
	    }
	  delete vptr;
	}
      if (!ext.empty() && !compat && ((constant = conf->constantByName("extension-type")) != NULL))
	{
	  values = constant->values();
	  it = values.begin();
	  while (it != values.end() && !compat)
	    {
	      if ((*it)->type() == typeId::String && (*it)->value<std::string>().find(ext) != std::string::npos)
		compat = true;
	      it++;
	    }
	}
    }
  return compat;
}


VfsRoot::VfsRoot(std::string name): Node(name)
{
  this->setParent(this);
  this->setDir();
}

VfsRoot::~VfsRoot()
{
}
