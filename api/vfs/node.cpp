/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 *  Solal J. <sja@digital-forensic.org>
 */

#include "node.hpp"

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

Attributes	Node::_attributes(void)
{
  Attributes attr;

  return (attr);
}


void 	Node::attributesByTypeFromVariant(Variant* variant, uint8_t type, Attributes* result)
{
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
       if ((*it).second->type() == type)
	 (*result)[(*it).first] = (*it).second;
       else
	 this->attributesByTypeFromVariant((*it).second, type, result);
   }
}

void	Node::attributesByNameFromVariant(Variant* variant, std::string name, Variant** result)
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
       if ((*it).first == name)
       {
	  *result = (*it).second;
	  return;
       }
       else
	 this->attributesByNameFromVariant((*it).second, name, result);
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
	 names->push_back((*it).first);
	 this->attributesNamesFromVariant((*it).second, names);
     }
   }

}


std::list<std::string>*  	Node::attributesNames(void)
{
 std::list<std::string>*	result = new std::list<std::string>;
 Attributes*			attr = this->attributes();
 Variant*			var = new Variant(*attr);

 this->attributesNamesFromVariant(var, result);

 return (result);
}

Variant*			Node::attributesByName(std::string name)
{
 Attributes*			attr = this->attributes();
 Variant*			var = new Variant(*attr);
 Variant**			result = new Variant *; 

 *result = NULL; 
 this->attributesByNameFromVariant(var, name, result);

 return (*result);
}

Attributes*			Node::attributesByType(uint8_t type)
{
 Attributes*			result = new Attributes;
 Attributes*			attr = this->attributes();
 Variant*			var = new Variant(*attr);
  
 this->attributesByTypeFromVariant(var, type, result);

 return result;
}


Attributes*			Node::attributes() //rajouter un wait times ->bloquant ou pas 
{
  Attributes* attr = new std::map<std::string, Variant*>;
//UNICODE
   (*attr)[std::string("type")] = this->dataType(); //TYPE A REGISTER DS LE NODE OU AVOIR UN REGISTER GLOBAL ?

  std::set<AttributesHandler*>::iterator handler;
  Attributes	nodeAttributes = this->_attributes();
  if (!(nodeAttributes.empty()))
    (*attr)[this->fsobj()->name] = new Variant(nodeAttributes);
  for (handler = this->__attributesHandlers.begin(); handler != this->__attributesHandlers.end(); handler++)
  {
    (*attr)[(*handler)->name()] = new Variant((*handler)->attributes(this));	
  } 	

  return attr;
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
   return (this->__attributesHandlers.insert(ah).second);
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
  if (0) {
	// FIXME check if child already present
	return false;
  }
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

Variant*	Node::dataType(/*uint32_t wait = 0*event callback*/) /*au lieux de void mettre type mime ou ...? */
{
  Variant*	types = NULL;
  std::map<std::string, Variant*>	attributes;

//threader ? 
//  if thread.wait(wait) 
//{

  class DataTypeManager&	typeDB = DataTypeManager::Get();
  types = typeDB.type(this);  //dynamic type
 //}

  //ret none if types    
  return types; 
}

std::list<std::string>*		Node::compatibleModules(void)
{
  // XXX variantBaseAPI !!!
  //  class env*	environ    = env::Get();
  //  v_key*  keys  	   = environ->vars_db["mime-type"];
  //  list<class v_val*> vals = keys->val_l;  
  //  list<std::string > *res = new list<std::string>(); 
  //  std::list<class v_val*>::iterator val;
  //  Attributes::iterator var;

  //  for (val = vals.begin(); val != vals.end(); val++)
  //  {
  //    if ((*val)->type == "string")
  //    {
  //      Attributes 	vars = this->dataType()->value<Attributes >();
  //      for (var = vars.begin(); var != vars.end(); var++)
  //      { 
  //        if (((*var).second)->value<std::string>().find((*val)->get_string()) != -1)
  //        {
  //          res->push_back((*val)->from);
  // 	   //delete (*var);
  //        }
  //      }
  //    }
  //  }
  // return res;
// XXX variantBaseAPI !!!
}

bool	Node::isCompatibleModule(string modname)
{
   list<std::string > *mods = this->compatibleModules();
   std::list<std::string>::iterator it;

   for (it = mods->begin(); it != mods->end(); it++)
     if (modname == (*it))
     {
        delete mods;
	return true;
     }
   delete mods;
//   if node.size() and modules["modname"].conf == data:
// HASH prob because NONE 
//XXX file me use reverse arg methode
/*    std::string type = 
    if node.dataType.find(modname)	
      return true;*/
    return false;
}


VfsRoot::VfsRoot(std::string name): Node(name)
{
  this->setParent(this);
  this->setDir();
}

VfsRoot::~VfsRoot()
{
}
