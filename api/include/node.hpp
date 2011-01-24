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
#include "vtime.hpp"
#include "exceptions.hpp"
#include "datatype.hpp"

typedef std::map<std::string, class Variant* > Attributes; 

class AttributesHandler
{
  	std::string	__handlerName;
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
  //uint64_t                    offset;

  //XXX parent could be a list of Node. 
  //    Ex: Raid reconstruction based on two nodes which
  //    are aggregated to only one Node
  class Node*			__parent;
  list<AttributesHandler*>	__attributesHandlers;

  std::vector<class Node *>	__children;
  uint32_t			__childcount;
  std::string			__name;
  uint64_t			__size;
  class fso*			__fsobj;
  uint64_t			__common_attributes;
  std::map<std::string, class Variant*> __static_attributes;
  //unsigned char			__checkState;
  uint32_t			__id; //FIX for local and mfso / fso mess in reimplation of vopen 
  EXPORT virtual Attributes	_attributes();
  EXPORT void			attributesByTypeFromVariant(Variant*, uint8_t, Attributes*);
  EXPORT void	 		attributesByNameFromVariant(Variant* variant, std::string name, Variant**);
  EXPORT void	 		attributesNamesFromVariant(Variant* variant, std::list<std::string>* names);
public:
  uint32_t			__at;
  EXPORT Node(std::string name, uint64_t size=0, Node* parent=NULL, fso* fsobj=NULL);
  EXPORT Node();
  EXPORT virtual 			~Node();


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

  EXPORT virtual class VFile*		open();
  EXPORT uint32_t			at();


  EXPORT bool					registerAttributes(AttributesHandler*);
  EXPORT virtual class Variant*			dataType(void); 
  EXPORT virtual Attributes*			attributes();	
  EXPORT virtual Variant*			attributesByName(std::string);
  EXPORT virtual Attributes*			attributesByType(uint8_t type);
  EXPORT virtual std::list<std::string>*	attributesNames(void);

  EXPORT virtual string				icon();
  EXPORT virtual std::list<std::string>*	compatibleModules(void);
  EXPORT virtual bool				isCompatibleModule(string);
};

class VfsRoot: public Node
{
public:
  VfsRoot(std::string name);
  ~VfsRoot();
};

class VLink : public Node
{
private :
  Node* 			__linkedNode;
public :

  EXPORT uint32_t			id();
  EXPORT void				fileMapping(FileMapping *);
  EXPORT uint64_t			size();

  EXPORT std::string			linkPath();
  EXPORT std::string			linkName();
  EXPORT std::string			linkAbsolute();

  EXPORT bool				isFile();
  EXPORT bool				isDir();
  EXPORT bool				isLink();
  EXPORT bool				isVDir();
  EXPORT bool				isDeleted();

  EXPORT class fso*			fsobj();
  EXPORT class VFile*			open();

  EXPORT VLink(Node *linkedNode, Node* parent, std::string newname = "");
  EXPORT ~VLink();
  EXPORT  Node*				linkParent();
  EXPORT std::vector<class Node*>	linkChildren();
  EXPORT bool				linkHasChildren();
  EXPORT uint32_t			linkChildCount();
  EXPORT Node*				linkNode();

  EXPORT Variant*			dataType(void); 
  EXPORT Attributes*			attributes(void);	
  EXPORT std::string			icon(void);
  EXPORT std::list<std::string>*	compatibleModules(void);
  EXPORT bool				isCompatibleModule(std::string);
};


#endif
