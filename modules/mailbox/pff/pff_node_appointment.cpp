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


//XXX pas top herite de PffNodeEMail juste pour une fonctions des attribute voir 2 mais ds le cas d example y en a qu une de valide : tramsport header ou ...
//XXX on copy l 'item et one le free pas ds attachment pas ce que si non ca marche pas, et aussi on ne peut pas clone les appointment donc on le sprend par identifier 
// fautdrait peut etre prendre teoute les node par identifier ? mais est-ce que y a pas un bug equivalent certain qui se clone mais qui s identifie pas ? 
//XXX cleaner tous ca si possible + renvoyer bug patch au monsieur 

PffNodeAppointment::PffNodeAppointment(std::string name, Node* parent, fso* fsobj, libpff_item_t* appointment, libpff_error_t** error, libpff_file_t** file) : PffNodeEMail(name, parent, fsobj, appointment, error)
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
  //if (libfdatetime_filetime_initialize(&filetime, this->pff_error) != 1)
  //return ;
  result = libpff_appointment_get_start_time((*this->item), &entry_value_64bit, this->pff_error);
  if (result != -1 && result != 0)
  {
     vtime* 	start_time = new vtime;
     msDateToVTime(entry_value_64bit, start_time);
     Variant*  vstart_time = new Variant(start_time);
     (*attr)["start time"] = vstart_time;
  }
  result = libpff_appointment_get_end_time(*(this->item), &entry_value_64bit, this->pff_error);
  if (result != -1 && result != 0)
  {
     vtime*  	end_time = new vtime;
     msDateToVTime(entry_value_64bit, end_time);
     Variant*  vstart_time = new Variant(end_time);
     (*attr)[std::string("end time")] = vstart_time;
  }
  //8515
  result = libpff_appointment_get_duration(*(this->item), &entry_value_32bit, this->pff_error);
  if (result  != -1 && result != 0)
  {
     (*attr)[std::string("Duration")] = new Variant(entry_value_32bit);
  }
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
  result = libpff_appointment_first_effective_time(*(this->item), &entry_value_64bit, this->pff_error);
  if (result != 0 && result != -1)
  {
     vtime*  	first_effective_time = new vtime;
     msDateToVTime(entry_value_64bit, first_effective_time);
     Variant*  vfirst_effective_time = new Variant(first_effective_time);
     (*attr)[std::string("First effective time")] = vfirst_effective_time;
  }
  result = libpff_appointment_last_effective_time(*(this->item), &entry_value_64bit, this->pff_error);
  if (result != 0 && result != -1)
  {
     vtime*  	first_effective_time = new vtime;
     msDateToVTime(entry_value_64bit, first_effective_time);
     Variant*  vfirst_effective_time = new Variant(first_effective_time);
     (*attr)[std::string("Last effective time")] = vfirst_effective_time;
  }
  result = libpff_appointment_get_busy_status(*(this->item), &entry_value_32bit, this->pff_error);
  if (result != -1 && result != 0)
  {
     (*attr)[std::string("Busy status")] = new Variant(entry_value_32bit);
  }
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

