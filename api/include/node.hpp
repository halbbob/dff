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

#ifndef __NODE_HPP__
#define __NODE_HPP__

#include <string>
#include <map>
#include <vector>
#include <set>
#include <iostream>
#include <sys/types.h>
#include "fso.hpp"
#include "export.hpp"
#include "filemapping.hpp"
#include "vfile.hpp"
#include "variant.hpp"
#include "confmanager.hpp"
#include "vtime.hpp"
#include "exceptions.hpp"
#include "datatype.hpp"

typedef std::map<std::string, class Variant* > Attributes; 

enum	attributeNameType
  {
    ABSOLUTE_ATTR_NAME = 0,
    RELATIVE_ATTR_NAME = 1
  };

// #define ABSOLUTE_ATTR_NAME	0x1
// #define RELATIVE_ATTR_NAME	0x2

class AttributesHandler
{
  	std::string		__handlerName;
public:
  EXPORT			AttributesHandler(std::string handlerName);
  EXPORT virtual		~AttributesHandler();
  EXPORT virtual Attributes 	attributes(class Node*) = 0;
  EXPORT std::string		name(void);
};

#define ISFILE		0x01
#define ISDIR		0x02
#define ISLINK		0x04
#define ISDELETED	0x08

class Node
{
protected:
  class Node*				__parent;
  std::set<AttributesHandler*>		__attributesHandlers; 
  std::vector<class Node *>		__children;
  uint32_t				__childcount;
  std::string				__name;
  uint64_t				__size;
  class fso*				__fsobj;
  uint64_t				__common_attributes;
  //unsigned char			__checkState;
  uint32_t				__id;
  uint64_t				__uid;
  EXPORT virtual Attributes		_attributes();
  EXPORT void				attributesByTypeFromVariant(Variant*, uint8_t, Attributes*);
  EXPORT void				attributesByTypeFromVariant(Variant*, uint8_t, Attributes*, std::string current);

  EXPORT void	 			attributesByNameFromVariant(Variant* variant, std::string name, Variant**);
  EXPORT void	 			attributeByAbsoluteNameFromVariant(Variant* variant, std::string name, Variant**);

  EXPORT void	 			attributesNamesFromVariant(Variant* variant, std::list<std::string>* names);
  EXPORT void	 			attributesNamesFromVariant(Variant* variant, std::list<std::string>* names, std::string current);

  EXPORT void				attributesNamesAndTypesFromVariant(Variant* variant, std::map<std::string, uint8_t> *namestypes, std::string current);
  EXPORT bool				constantValuesMatch(Constant* constant, Attributes vars);
public:
  EXPORT 				Node(std::string name, uint64_t size=0, Node* parent=NULL, fso* fsobj=NULL);
  EXPORT 				Node();
  EXPORT virtual 			~Node();

  uint32_t				__at;

  EXPORT void				setId(uint32_t	id);
  EXPORT virtual	uint32_t	id();

  EXPORT void				setFile();
  EXPORT void				setDir();
  EXPORT void				setLink();
  EXPORT void				setDeleted();
  EXPORT void				setSize(uint64_t size);
  EXPORT void				setFsobj(fso* obj);
  EXPORT void				setParent(Node* parent);

  EXPORT virtual void			fileMapping(FileMapping *);
  EXPORT virtual uint64_t		size();

  EXPORT std::string			path();
  EXPORT std::string			name();
  EXPORT std::string			absolute();

  EXPORT virtual bool			isFile();
  EXPORT virtual bool			isDir();
  EXPORT virtual bool			isLink();
  EXPORT virtual bool			isVDir();
  EXPORT virtual bool			isDeleted();

  EXPORT virtual class fso*		fsobj();

  EXPORT Node*				parent();

  EXPORT std::vector<class Node*>	children();
  EXPORT bool				addChild(class Node* child);
  EXPORT bool				hasChildren();
  EXPORT uint32_t			childCount();
  EXPORT uint64_t			totalChildrenCount();

  EXPORT virtual class VFile*		open();
  EXPORT uint32_t			at();

  EXPORT uint64_t			uid();

  EXPORT bool					registerAttributes(AttributesHandler*);
  EXPORT virtual class Variant*			dataType(void); 
  EXPORT virtual Attributes*			attributes();
  EXPORT virtual Variant*			attributesByName(std::string, attributeNameType tname=RELATIVE_ATTR_NAME);
  EXPORT virtual Attributes*			attributesByType(uint8_t type, attributeNameType tname=RELATIVE_ATTR_NAME);
  EXPORT virtual std::list<std::string>*	attributesNames(attributeNameType tname=RELATIVE_ATTR_NAME);
  //EXPORT virtual std::list<std::string>*	absoluteAttributesNames(void);

  EXPORT virtual std::map<std::string, uint8_t>*	attributesNamesAndTypes();
  EXPORT virtual string				icon();
  EXPORT virtual std::list<std::string>*	compatibleModules(void);
  EXPORT virtual bool				isCompatibleModule(string);
  EXPORT virtual Attributes*			dynamicAttributes(void);
  EXPORT virtual Variant*			dynamicAttributes(std::string name);
  EXPORT virtual std::list<std::string>*	dynamicAttributesNames(void);
  EXPORT virtual Attributes			fsoAttributes();
};

class VfsRoot: public Node
{
public:
  VfsRoot(std::string name);
  ~VfsRoot();
};

#endif
