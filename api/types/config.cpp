/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal J. <sja@digital-forensic.org>
 *  Frederic B. <fba@digital-forensic.org>
 */

#include "config.hpp"

Config::Config(std::string origin, std::string description)
{
  this->__origin = origin;
  this->__description = description;
}

Config::~Config()
{
}

// void			Config::add(std::string name, uint8_t type, bool optional, std::string description)
// {
//   Argument*		param;

//   if (this->__parameters.find(name) == this->__parameters.end())
//     {
//       param = new Argument(type, optional, description);
//       this->__parameters.insert(std::pair<std::string, Argument* >(name, param));
//     }
//   else
//     std::cout << "param already present" << std::endl;
// }

std::string		Config::origin()
{
  return this->__origin;
}

std::string		Config::description()
{
  return this->__description;
}

Argument*		Config::addArgument(std::string name, uint16_t type, std::string description)
{
  
}



// std::map<std::string, Argument* >	Config::parameters()
// {
//   return this->__parameters;
// }


// bool		Config::isContainerCompatible(std::map<std::string, Variant*> vmap)
// {
//   std::map<std::string, Variant*>::iterator	it;
//   bool						ret;
  
//   ret = true;
//   it = vmap.begin();
//   while ((it != vmap.end()) && (ret == true))
//     {
//       if ((*it).second->type() != this->__type)
// 	ret = false;
//       it++;
//     }
//   return ret;
// }


// bool		Config::isContainerCompatible(std::list<Variant*> vlist)
// {
//   std::list<Variant*>::iterator	it;
//   bool				ret;
  
//   ret = true;
//   std::cout << vlist.size() << std::endl;
//   it = vlist.begin();
//   while ((it != vlist.end()) && (ret == true))
//     {
//       printf("%d | %d\n", (*it)->type(), this->__type);
//       if ((*it)->type() != this->__type)
// 	ret = false;
//       it++;
//     }
//   std::cout << "ENDED" << std::endl;
//   return ret;
// }

// bool		Config::isDefaultCompatible(Variant *defaults)
// {
//   bool		ret;
//   uint8_t	dtype;
  
//   ret = false;
//   dtype = defaults->type();
//   if (dtype == this->__type)
//     ret = true;
//   else if (dtype == typeId::List)
//     {
//       std::cout << "List" << std::endl;
//       ret = this->isContainerCompatible(defaults->value<std::list< Variant *> >());
//     }
//   else if (dtype == typeId::Map)
//     {
//       std::cout << "Map" << std::endl;
//       ret = this->isContainerCompatible(defaults->value<std::map<std::string, Variant*> >());
//     }
//   else
//     ret = false;
//   return ret;
// }

// std::list<Variant*>	Config::defaults()
// {
//   return this->__defaults;
// }

// bool		Config::add_const(std::string name, Variant* val)
// {
// //   if (this->isDefaultCompatible(val))
// //     this->__defaults.push_back(val);
// //   else
// //     std::cout << "wrong type" << std::endl;
// }



// std::string	Config::origin()
// {
//   return this->__origin;
// }

// Vars*		Config::__findVarsByName(std::string name)
// {
//   std::list<Vars*>::iterator	it;
//   bool				found;
//   Vars*				v;
  
//   found = false;
//   it = this->__configvars.begin();
//   while ((it != this->__configvars.end()) && (!found))
//     {
//       v = *it;
//       if (v->name() == name)
// 	found = true;
//       it++;
//     }
//   if (found)
//     return v;
//   else
//     return NULL;
// }

// std::list<Vars*>	Config::vars()
// {
//   return this->__configvars;
// }

// std::list<Vars*>	Config::defaults()
// {
//   return this->__defaultvars;
// }

// void 		Config::add_const(std::string name, Variant* val)
// {
//   //  Vars*		v;

// //   if ((v = this->__findVarsByName(name)) != NULL)
// //     {
// //       this->__defaultvars.push_back(v);
// //       v->addDefault(val);
// //     }
// //   else
// //     std::cout << "Config::add_const --> parameter " << name << " not found" << std::endl;
// }

// bool		Config::add(std::string name, uint8_t type, bool optional, std::string description)
// {
  
// //   Vars*		nvar;

// //   if (this->__findVarsByName(name) == NULL)
// //     {
// //       nvar = new Vars(this->__origin, name, optional, description, type);
// //       this->__configvars.push_back(nvar);
// //     }
// //   else
// //     std::cout << "vars " << name << " already exist" << std::endl;
// }
