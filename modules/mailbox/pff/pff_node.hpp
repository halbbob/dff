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
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __PFF_NODE_HH__
#define __PFF_NODE_HH__

#if __WORDSIZE == 64
#define NANOSECS_1601_TO_1970   (uint64_t)(116444736000000000UL)
#else
#define NANOSECS_1601_TO_1970   (uint64_t)(116444736000000000ULL)
#endif

#include "pff.hpp"
//#include "libpff-20110201/libpff/libpff_item.h"
#define check_maximum_size(func) \
  result = func(*(this->item), &entry_value_string_size, (this->pff_error)); \
  if (result != 0 && result != -1) \
  {\
    if (entry_value_string_size > maximum_entry_value_string_size)\
  	maximum_entry_value_string_size = entry_value_string_size;\
  }

#define value_string_to_attribute(func, key) \
  result = func(*(this->item), (uint8_t *)entry_value_string, \
maximum_entry_value_string_size, this->pff_error); \
  if (result != -1 && result != 0) \
    (*attr)[key] = new Variant(std::string(entry_value_string));

#define value_time_to_attribute(func, key) \
  result = func((*this->item), &entry_value_64bit, this->pff_error); \
  if (result != -1 && result != 0) \
  { \
     vtime* 	value_time = new vtime; \
     msDateToVTime(entry_value_64bit, value_time); \
     Variant*  variant_time = new Variant(value_time); \
     (*attr)[key] = variant_time; \
  }

#define value_uint32_to_attribute(func, key) \
  result = func(*(this->item), &entry_value_32bit, this->pff_error); \
  if (result  != -1 && result != 0) \
  {\
     (*attr)[key] = new Variant(entry_value_32bit); \
  }


bool         msDateToVTime(uint64_t value, vtime *setMe); //XXX api XXX ntfs XXX windows

class PffNodeFolder : public Node
{
public:
  EXPORT PffNodeFolder(std::string name, Node* parent, fso* fsobj);
  EXPORT ~PffNodeFolder();
  std::string		icon(void);
};

class PffNodeData : public Node
{
public:
  EXPORT 		        PffNodeData(std::string name, Node* parent, fso* fsobj, libpff_error_t**);
  EXPORT 		        PffNodeData(std::string name, Node* parent, fso* fsobj, libpff_item_t *dataItem, libpff_error_t**);
  virtual fdinfo*       	vopen();
  virtual int32_t 	        vread(fdinfo* fi, void *buff, unsigned int size);
  virtual int32_t 	        vclose(fdinfo* fi);
  virtual uint64_t      	vseek(fdinfo* fi, uint64_t offset, int whence);
  libpff_error_t**	        pff_error;
  libpff_item_t**       	item;
};

class PffNodeEMail : public PffNodeData
{
private:
  void 			        attributesMessageHeader(Attributes* attr);
  void 			        attributesMessageConversationIndex(Attributes* attr);
  void			        attributesRecipients(Attributes* attr);
  void			        attributesTransportHeaders(Attributes* attr);
  void 			        splitTextToAttributes(std::string text, Attributes* attr);
public:
  EXPORT 		        PffNodeEMail(std::string name, Node* parent, fso* fsobj, libpff_error_t**);
  EXPORT 		        PffNodeEMail(std::string name, Node* parent, fso* fsobj, libpff_item_t *mail, libpff_error_t**);
  EXPORT virtual Attributes     _attributes(void);
  fdinfo*       		vopen(void);
  int32_t 	       	 	vread(fdinfo* fi, void *buff, unsigned int size);
  int32_t 	        	vclose(fdinfo* fi);
  uint64_t		      	vseek(fdinfo* fi, uint64_t offset, int whence);
  virtual uint8_t *	        dataBuffer(void);
  std::string			icon(void);

//set icon
};

class PffNodeEmailTransportHeaders : public PffNodeEMail
{
public:
  EXPORT		        PffNodeEmailTransportHeaders(std::string, Node*, fso*, libpff_item_t*, libpff_error_t**);
  EXPORT uint8_t *	        dataBuffer(void);
//set icon
};

class PffNodeEmailMessageText : public PffNodeEMail
{
public:
  EXPORT			PffNodeEmailMessageText(std::string , Node*, fso*, libpff_item_t*, libpff_error_t**);
  EXPORT uint8_t*		dataBuffer(void);
};

class PffNodeEmailMessageHTML : public PffNodeEMail
{
public:
  EXPORT			PffNodeEmailMessageHTML(std::string , Node*, fso*, libpff_item_t*, libpff_error_t**);
  EXPORT uint8_t*		dataBuffer(void);
};

class PffNodeEmailMessageRTF : public PffNodeEMail
{
public:
  EXPORT			PffNodeEmailMessageRTF(std::string , Node*, fso*, libpff_item_t*, libpff_error_t**);
  EXPORT uint8_t*		dataBuffer(void);
};

//class PffNodeAttachment : public PffNodeData
class PffNodeAttachment : public PffNodeEMail 
{
private:
public:
  EXPORT 		        PffNodeAttachment(std::string name, Node* parent, fso* fsobj, libpff_item_t *mail, libpff_error_t**, size64_t);
//  EXPORT virtual Attributes     _attributes(void);
  EXPORT uint8_t*		dataBuffer(void);
  EXPORT std::string		icon(void);

//fdinfo*       		vopen(void);
//int32_t 	       	 	vread(fdinfo* fi, void *buff, unsigned int size);
//int32_t 	        	vclose(fdinfo* fi);
//uint64_t   		   	vseek(fdinfo* fi, uint64_t offset, int whence);
//set icon
};

class PffNodeAppointment : public PffNodeEMail
{
//use identifier because clone didn't work here ! use it very were ? test memory usage & perf !
 libpff_file_t**	pff_file;
 uint32_t		identifier;
public:
 EXPORT	PffNodeAppointment(std::string name, Node *parent, fso* fsobj, libpff_item_t* appointment, libpff_error_t**, libpff_file_t**);
 EXPORT virtual Attributes     _attributes(void);
 EXPORT void  	               attributesAppointment(Attributes* attr);
};


class PffNodeContact : public PffNodeEMail
{
  public:
 EXPORT PffNodeContact(std::string name, Node* parent, fso* fsobj, libpff_item_t* contact, libpff_error_t**);
 EXPORT virtual Attributes 	_attributes(void);
 EXPORT void			attributesContact(Attributes* attr);
 EXPORT uint8_t*		dataBuffer(void); 
};

class PffNodeTask : public PffNodeEMail
{
  libpff_file_t**	pff_file;
  uint32_t		identifier;
  public:
  EXPORT PffNodeTask(std::string name, Node* parent, fso* fsobj, libpff_item_t* task, libpff_error_t**, libpff_file_t** file);
  EXPORT virtual Attributes   _attributes(void);
  EXPORT void		      attributesTask(Attributes* attr); 
  EXPORT uint8_t*		dataBuffer(void); 
};

class PffNodeUnallocatedBlocks : public Node
{
private:
 Node*			root;
 int			block_type;
 libpff_error_t**	pff_error;
 libpff_file_t**	pff_file;
 uint32_t		identifier;
public:
 EXPORT			PffNodeUnallocatedBlocks(std::string name, Node* parent, mfso* fsobj, Node* root,int block_type, libpff_error_t**, libpff_file_t**);
 virtual void		fileMapping(FileMapping* fm);
};

#endif
