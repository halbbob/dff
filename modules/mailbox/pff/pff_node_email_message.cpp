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

#include "pff.hpp"


PffNodeEmailMessageText::PffNodeEmailMessageText(std::string name, Node* parent, fso* fsobj, libpff_item_t *mail, libpff_error_t** error) : PffNodeEMail(name, parent, fsobj, mail, error)
{
  size_t 	headers_size  = 0; 

  if (libpff_message_get_plain_text_body_size(*(this->item), &headers_size, this->pff_error) == 1)
  {
    if (headers_size > 0)
       this->setSize(headers_size); 
  }
}

// 9335 export_handle_export_message_body
//export_handle_export_message_body_plain_text
uint8_t*	PffNodeEmailMessageText::dataBuffer(void)
{
  uint8_t*	entry_string = NULL;

  if (this->size() <= 0)
    return (NULL);
	
  entry_string =  new uint8_t [this->size()];
	
  if (libpff_message_get_plain_text_body(*(this->item), entry_string, this->size(), this->pff_error ) != 1 )
  {
    delete entry_string;
    return (NULL);
  }

  return (entry_string);
}


PffNodeEmailMessageHTML::PffNodeEmailMessageHTML(std::string name, Node* parent, fso* fsobj, libpff_item_t *mail, libpff_error_t** error) : PffNodeEMail(name, parent, fsobj, mail, error)
{
  size_t 	headers_size  = 0; 

  if (libpff_message_get_html_body_size(*(this->item), &headers_size, this->pff_error) == 1)
  {
    if (headers_size > 0)
       this->setSize(headers_size); 
  }
}

// 9335 export_handle_export_message_body
//export_handle_export_message_body_plain_text
uint8_t*	PffNodeEmailMessageHTML::dataBuffer(void)
{
  uint8_t*	entry_string = NULL;

  if (this->size() <= 0)
    return (NULL);
	
  entry_string =  new uint8_t [this->size()];
	
  if (libpff_message_get_html_body(*(this->item), entry_string, this->size(), this->pff_error ) != 1 )
  {
    delete entry_string;
    return (NULL);
  }

  return (entry_string);
}

PffNodeEmailMessageRTF::PffNodeEmailMessageRTF(std::string name, Node* parent, fso* fsobj, libpff_item_t *mail, libpff_error_t** error) : PffNodeEMail(name, parent, fsobj, mail, error)
{
  size_t 	headers_size  = 0; 

  if (libpff_message_get_rtf_body_size(*(this->item), &headers_size, this->pff_error) == 1)
  {
    if (headers_size > 0)
       this->setSize(headers_size); 
  }
}

// 9335 export_handle_export_message_body
//export_handle_export_message_body_plain_text
uint8_t*	PffNodeEmailMessageRTF::dataBuffer(void)
{
  uint8_t*	entry_string = NULL;

  if (this->size() <= 0)
    return (NULL);
	
  entry_string =  new uint8_t [this->size()];
	
  if (libpff_message_get_rtf_body(*(this->item), entry_string, this->size(), this->pff_error ) != 1 )
  {
    delete entry_string;
    return (NULL);
  }

  return (entry_string);
}
