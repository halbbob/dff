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



PffNodeAppointment::PffNodeAppointment(std::string name, Node* parent, fso* fsobj, libpff_item_t* appointment, libpff_error_t** error, libpff_file_t** file) : PffNodeEMail(name, parent, fsobj, error)
{
  libpff_item_get_identifier(appointment, &(this->identifier), error);
  this->pff_error = error;
  this->pff_file = file;

  this->item = new libpff_item_t*; 
  *(this->item) = NULL;


  if (libpff_file_get_item_by_identifier(*(this->pff_file), this->identifier, this->item, this->pff_error) == 0)
  {
    (*this->item) = appointment; 
  }
//ds attribute pour pas prendre en ram ? 
}


void  PffNodeAppointment::attributesAppointment(Attributes* attr)
{
  char*		entry_value_string 		= NULL;
  size_t	entry_value_string_size         = 0;
  size_t	maximum_entry_value_string_size	= 1;
  uint64_t	entry_value_64bit               = 0;
  uint32_t	entry_value_32bit               = 0;
  int 		result                          = 0;

  // UTF8 possible UTF16
  if (libpff_appointment_get_utf8_location_size((*this->item), &entry_value_string_size, this->pff_error) == -1)
  return ;

  if (entry_value_string_size > maximum_entry_value_string_size)
       maximum_entry_value_string_size = entry_value_string_size;
  result = libpff_appointment_get_utf8_recurrence_pattern_size(*(this->item), &entry_value_string_size, this->pff_error);
  if (result == -1)
    return ;
  else if (result != 0)
  {
    if (entry_value_string_size > maximum_entry_value_string_size)
       maximum_entry_value_string_size = entry_value_string_size;
  }
  if (maximum_entry_value_string_size == 0)
	return ;
  entry_value_string = (char *)malloc(sizeof(char *) * maximum_entry_value_string_size);
  if (entry_value_string == NULL)
     return ;

  value_time_to_attribute(libpff_appointment_get_start_time, "Start time")
  value_time_to_attribute(libpff_appointment_get_end_time, "End time")

  value_uint32_to_attribute(libpff_appointment_get_duration, "Duration")

  result = libpff_appointment_get_utf8_location(*(this->item), (uint8_t *) entry_value_string, maximum_entry_value_string_size, this->pff_error);
  if (result != -1 && result != 0)
  {
     (*attr)["Location"] = new Variant(std::string(entry_value_string));
  }
  //appointment recurence pattern 8583
  result = libpff_appointment_get_utf8_recurrence_pattern(*(this->item), (uint8_t *) entry_value_string , maximum_entry_value_string_size, this->pff_error);
  if (result != -1 && result != 0)
    (*attr)["Recurrence pattern"] = new Variant(std::string(entry_value_string));
//libpff_apointment first effectime time

  value_time_to_attribute(libpff_appointment_first_effective_time, "First effective time")
  value_time_to_attribute(libpff_appointment_last_effective_time,  "Last effective time")


  value_uint32_to_attribute(libpff_appointment_get_busy_status, "Busy status")
/* 
  result = libpff_appointment_get_busy_status(*(this->item), &entry_value_32bit, this->pff_error);
  if (result != -1 && result != 0)
  {
     (*attr)[std::string("Busy status")] = new Variant(entry_value_32bit);
  }
*/

  free(entry_value_string);
}


Attributes PffNodeAppointment::_attributes()
{
//use mail default attribute and add appointment attriubtes
  Attributes attr = PffNodeEMail::_attributes();

  Attributes appointment;
  this->attributesAppointment(&appointment); 
  attr[std::string("Appointment")] = new Variant(appointment);
//add specific attribute for apointment here

  return attr;
}

