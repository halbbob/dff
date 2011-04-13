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

PffNodeContact::PffNodeContact(std::string name, Node* parent, fso* fsobj, libpff_item_t* contact, libpff_error_t** error) : PffNodeEMail(name, parent, fsobj, contact, error)
{
  size_t 	headers_size  = 0; 

  if (libpff_message_get_plain_text_body_size(*(this->item), &headers_size, this->pff_error) == 1)
  {
    if (headers_size > 0)
       this->setSize(headers_size); 
  }
}

Attributes	PffNodeContact::_attributes(void)
{
  Attributes	attr = PffNodeEMail::_attributes();
  
  Attributes	contact;
  this->attributesContact(&contact);
  attr[std::string("Contact")] = new Variant(contact);

  return (attr);
}

void		PffNodeContact::attributesContact(Attributes* attr)
{
  char*		entry_value_string		= 0;
  size_t	entry_value_string_size 	= 0;
  size_t	maximum_entry_value_string_size	= 1;
  int		result				= 0;

  check_maximum_size(libpff_address_get_utf8_file_under_size)
  check_maximum_size(libpff_contact_get_utf8_given_name_size)
  check_maximum_size(libpff_contact_get_utf8_initials_size)
  check_maximum_size(libpff_contact_get_utf8_surname_size)
  check_maximum_size(libpff_contact_get_utf8_generational_abbreviation_size)
  check_maximum_size(libpff_contact_get_utf8_title_size)
  check_maximum_size(libpff_contact_get_utf8_callback_phone_number_size)
  check_maximum_size(libpff_contact_get_utf8_primary_phone_number_size)
  check_maximum_size(libpff_contact_get_utf8_home_phone_number_size)
  check_maximum_size(libpff_contact_get_utf8_mobile_phone_number_size)
  check_maximum_size(libpff_contact_get_utf8_company_name_size)
  check_maximum_size(libpff_contact_get_utf8_job_title_size)
  check_maximum_size(libpff_contact_get_utf8_postal_address_size)
  check_maximum_size(libpff_contact_get_utf8_office_location_size)
  check_maximum_size(libpff_contact_get_utf8_department_name_size)
  check_maximum_size(libpff_contact_get_utf8_country_size)
  check_maximum_size(libpff_contact_get_utf8_locality_size)
  check_maximum_size(libpff_contact_get_utf8_business_phone_number_1_size)
  check_maximum_size(libpff_contact_get_utf8_business_phone_number_2_size)
  check_maximum_size(libpff_contact_get_utf8_business_fax_number_size)

  if (maximum_entry_value_string_size == 0)
    return ;
  entry_value_string = (char *)malloc(sizeof(char*) * maximum_entry_value_string_size);
  if (entry_value_string ==  NULL)
    return ;

  value_string_to_attribute(libpff_address_get_utf8_file_under, "File under")
  value_string_to_attribute(libpff_contact_get_utf8_given_name, "Given name")
  value_string_to_attribute(libpff_contact_get_utf8_initials, "Initials")
  value_string_to_attribute(libpff_contact_get_utf8_surname, "Surname")
  value_string_to_attribute(libpff_contact_get_utf8_generational_abbreviation, "Generational abbreviation")
  value_string_to_attribute(libpff_contact_get_utf8_title, "Title")
  value_string_to_attribute(libpff_contact_get_utf8_callback_phone_number, "Callback phone number")
  value_string_to_attribute(libpff_contact_get_utf8_primary_phone_number, "Primary phone number")
  value_string_to_attribute(libpff_contact_get_utf8_home_phone_number, "Home phone number")
  value_string_to_attribute(libpff_contact_get_utf8_mobile_phone_number, "Mobile phone number")
  value_string_to_attribute(libpff_contact_get_utf8_company_name, "Company name")
  value_string_to_attribute(libpff_contact_get_utf8_job_title, "Job title")
  value_string_to_attribute(libpff_contact_get_utf8_office_location, "Office location")
  value_string_to_attribute(libpff_contact_get_utf8_department_name, "Department name")
  value_string_to_attribute(libpff_contact_get_utf8_postal_address, "Postal address")
  value_string_to_attribute(libpff_contact_get_utf8_country, "Country")
  value_string_to_attribute(libpff_contact_get_utf8_locality, "Locality")
  value_string_to_attribute(libpff_contact_get_utf8_business_phone_number_1, "Primary business phone number")
  value_string_to_attribute(libpff_contact_get_utf8_business_phone_number_2, "Secondary business phone nubmer")
  value_string_to_attribute(libpff_contact_get_utf8_business_fax_number, "Business fax number")
  
  free(entry_value_string);
  entry_value_string = NULL; 
}


uint8_t*	PffNodeContact::dataBuffer(void) //autant herite de mail_node_text directement
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
