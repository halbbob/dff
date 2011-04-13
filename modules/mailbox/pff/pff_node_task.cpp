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

PffNodeTask::PffNodeTask(std::string name, Node* parent, fso* fsobj, libpff_item_t* task, libpff_error_t** error, libpff_file_t** file) : PffNodeEMail(name, parent, fsobj, error)
{
  size_t 	headers_size  = 0; 

  libpff_item_get_identifier(task, &(this->identifier), error);

  this->pff_error = error;
  this->pff_file = file;
  this->item = new libpff_item_t*; 
  *(this->item) = NULL;

  if (libpff_file_get_item_by_identifier(*(this->pff_file), this->identifier, this->item, this->pff_error) == 0)
  {
	return ;
  }

  if (libpff_message_get_plain_text_body_size(*(this->item), &headers_size, this->pff_error) == 1)
  {
    if (headers_size > 0)
       this->setSize(headers_size); 
  }
}

Attributes	PffNodeTask::_attributes(void)
{
  Attributes	attr = PffNodeEMail::_attributes();

  Attributes	task;
  this->attributesTask(&task);
  attr[std::string("Task")] = new Variant(task);

  return attr;
}

void	PffNodeTask::attributesTask(Attributes*	attr)
{
  uint64_t	entry_value_64bit               = 0;
  uint32_t	entry_value_32bit               = 0;
  uint8_t	entry_value_boolean		= 0;
  double	entry_value_floating_point	= 0.0;
  int 		result                          = 0;

  value_time_to_attribute(libpff_task_start_date, "Start date")
  value_time_to_attribute(libpff_task_due_date, "Due date")

  value_uint32_to_attribute(libpff_task_get_status, "Status")
//task percentage float ! ... 13296 XXX fred

  value_uint32_to_attribute(libpff_task_get_actual_effort, "Actual effort")
  value_uint32_to_attribute(libpff_task_get_total_effort, "Total effort")
  //libpff_task_get_is_complete, //XXX boolean 13386
  result = libpff_task_get_is_complete(*(this->item), &entry_value_boolean, this->pff_error);
  if (result != -1 && result != 0) //utiliser variant boolean ? 
  {
     if (entry_value_boolean)
       (*attr)["Is complete"] = new Variant(std::string("yes"));
     else
       (*attr)["Is complete"] = new Variant(std::string("no"));
  } 



  value_uint32_to_attribute(libpff_task_get_version, "Version")
}

uint8_t*	PffNodeTask::dataBuffer(void) //autant herite de mail_node_text directement
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
