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

  check_maximum_size(libpff_appointment_get_utf8_location_size)
  check_maximum_size(libpff_appointment_get_utf8_recurrence_pattern_size) 

  if (maximum_entry_value_string_size == 0)
	return ;
  entry_value_string = (char *)malloc(sizeof(char *) * maximum_entry_value_string_size);
  if (entry_value_string == NULL)
     return ;

  value_time_to_attribute(libpff_appointment_get_start_time, "Start time")
  value_time_to_attribute(libpff_appointment_get_end_time, "End time")
  value_uint32_to_attribute(libpff_appointment_get_duration, "Duration")
  value_string_to_attribute(libpff_appointment_get_utf8_location, "Location")
  value_string_to_attribute(libpff_appointment_get_utf8_recurrence_pattern, "Recurrence pattern")
  value_time_to_attribute(libpff_appointment_first_effective_time, "First effective time")
  value_time_to_attribute(libpff_appointment_last_effective_time,  "Last effective time")
  value_uint32_to_attribute(libpff_appointment_get_busy_status, "Busy status")

  free(entry_value_string);
}


Attributes PffNodeAppointment::_attributes()
{
  Attributes attr = PffNodeEMail::_attributes();
  Attributes appointment;

  this->attributesAppointment(&appointment); 
  attr[std::string("Appointment")] = new Variant(appointment);

  return attr;
}

