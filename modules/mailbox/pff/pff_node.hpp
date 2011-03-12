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

//fdinfo*       		vopen(void);
//int32_t 	       	 	vread(fdinfo* fi, void *buff, unsigned int size);
//int32_t 	        	vclose(fdinfo* fi);
//uint64_t   		   	vseek(fdinfo* fi, uint64_t offset, int whence);
//set icon
};

class PffNodeUnallocatedPageBlocks : public Node
{
private:
 Node*			root;
 libpff_error_t**	pff_error;
 libpff_file_t**	pff_file;
public:
 EXPORT			PffNodeUnallocatedPageBlocks(std::string name, Node* parent, mfso* fsobj, Node* root, libpff_error_t**, libpff_file_t**);
 virtual void		fileMapping(FileMapping* fm);
};

#endif
