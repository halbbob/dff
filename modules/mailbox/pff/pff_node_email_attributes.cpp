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

libpff_macro32_s LIBPFF_MESSAGE_FLAG[9] = 
{
    //{ LIBPFF_MESSAGE_FLAG_READ, "Read" },
    // "Unread" },
    { LIBPFF_MESSAGE_FLAG_UNMODIFIED, "Unmodified" },
    { LIBPFF_MESSAGE_FLAG_SUBMIT, "Submit" },
    { LIBPFF_MESSAGE_FLAG_UNSENT, "Unsent" },
    { LIBPFF_MESSAGE_FLAG_HAS_ATTACHMENTS, "Has attachments" },
    { LIBPFF_MESSAGE_FLAG_FROM_ME, "From me" },
    { LIBPFF_MESSAGE_FLAG_ASSOCIATED, "Associated" },
    { LIBPFF_MESSAGE_FLAG_RESEND, "Resend" },
    { LIBPFF_MESSAGE_FLAG_RN_PENDING, "RN pending" },
    { LIBPFF_MESSAGE_FLAG_NRN_PENDING, "NRN pending" }
};

libpff_macro32_s LIBPFF_RECIPIENT_TYPE[4] = 
{
   { LIBPFF_RECIPIENT_TYPE_ORIGINATOR, "Originator"},
   { LIBPFF_RECIPIENT_TYPE_TO, "To"},
   { LIBPFF_RECIPIENT_TYPE_CC, "CC"},
   { LIBPFF_RECIPIENT_TYPE_BCC, "BCC"}
};


libpff_macro32_s LIBPFF_MESSAGE_IMPORTANCE_TYPE[3] = 
{
    { LIBPFF_MESSAGE_IMPORTANCE_TYPE_LOW, "Low"},
    { LIBPFF_MESSAGE_IMPORTANCE_TYPE_NORMAL, "Normal"},
    { LIBPFF_MESSAGE_IMPORTANCE_TYPE_HIGH, "High"}
}; 

libpff_macro32_s LIBPFF_MESSAGE_PRIORITY_TYPE[3] = 
{
    { LIBPFF_MESSAGE_PRIORITY_TYPE_NON_URGENT, "Non Urgent"},
    { LIBPFF_MESSAGE_PRIORITY_TYPE_NORMAL, "Normal"},
    { LIBPFF_MESSAGE_PRIORITY_TYPE_URGENT, "Urgent"}
}; 

libpff_macro32_s LIBPFF_MESSAGE_SENSITIVITY_TYPE[4] = 
{
    { LIBPFF_MESSAGE_SENSITIVITY_TYPE_NONE, "None"},
    { LIBPFF_MESSAGE_SENSITIVITY_TYPE_PERSONAL, "Personal"},
    { LIBPFF_MESSAGE_SENSITIVITY_TYPE_PRIVATE, "Private"},
    { LIBPFF_MESSAGE_SENSITIVITY_TYPE_CONFIDENTIAL, "Confidential"}
}; 



bool         msDateToVTime(uint64_t value, vtime *setMe)
{
  if (value > 0) {
    value -= NANOSECS_1601_TO_1970;
    value /= 10000000;
    struct tm   *date;

    date = gmtime((time_t *)&value);
    setMe->year = date->tm_year + 1900;
    setMe->month = date->tm_mon + 1;
    setMe->day = date->tm_mday;
    setMe->hour = date->tm_hour;
    setMe->minute = date->tm_min;
    setMe->second = date->tm_sec;
    setMe->dst = date->tm_isdst;
    setMe->wday = date->tm_wday;
    setMe->yday = date->tm_yday;
    setMe->usecond = 0;
    return true;
  }
  return false;
}

Attributes PffNodeEMail::_attributes()
{
//XXX options ds le modules pour choisir ce qu on veux en attribut, proposer transport
// header soit ds un fichier virtuel node soit en attribut

  Attributes attr;
//XXX maintenat qu on utilise des sous mrap faire un check et pas un return void sur les != attributes pour pas les push si error

  Attributes messageHeader;
  this->attributesMessageHeader(&messageHeader); //export message header 9147
  attr["Message Headers"] = new Variant(messageHeader);
//   this->attributesMessageConversationIndex(attr); //9174
// 9288 export_recipients
  Attributes recipients;
  this->attributesRecipients(&recipients);
  attr["Recipients"] = new Variant(recipients);

// 9315  export_handle_export_message_transport_headers
  Attributes transportHeaders;
  this->attributesTransportHeaders(&transportHeaders); //internetHEaders.txt
  attr["Transport Headers"] = new Variant(transportHeaders);
  return attr;
}

void PffNodeEMail::splitTextToAttributes(std::string text, Attributes* attr)
{
 //format 
 //attributes name: attributesValue -> multiline !  
 size_t 	splitter = 0;
 size_t		next_splitter = 0;
 size_t 	eol = 0;
 size_t 	next_eol = 0;
 size_t 	buff_size = text.length();
 std::string	key;
 std::string 	value;

 while (splitter < buff_size || next_eol + 3 < buff_size)
 {
   splitter = text.find(": ", splitter);
   if (splitter == string::npos)
     return ;
   eol = text.rfind("\n", splitter); 
   if (eol == string::npos)
   {
     eol = 0; 
     key = text.substr(eol, splitter - eol); 
   }
   else
     key = text.substr(eol + 1, splitter - eol - 1);
   next_splitter = text.find(": ", splitter + 1);
   if (next_splitter == string::npos)
     next_splitter = buff_size;

   next_eol = text.rfind("\n", next_splitter);
   if (next_eol == buff_size - 1)
     next_eol -= 2;

   size_t line = text.find("\n", splitter + 1);
   if (next_splitter < line)
   {
     next_splitter = text.find(": ", line);
     if (next_splitter == string::npos)
       next_splitter = buff_size;
 
     next_eol = text.rfind("\n", next_splitter);
     if (next_eol == string::npos)
       next_eol = buff_size; //it was == but now does it work ? fixed during appointment work
                
   }
   value = text.substr(splitter + 2,  next_eol - splitter - 3); 

   if (value.length() > 256)
     (*attr)[key] = new Variant(std::string("Value too long")); //XXX too field sometimes too long must be troncated in sub field
   else
   {
     (*attr)[key] = new Variant(value);
     //cout << "key:" << key << "-" << endl;
    // cout << "value:" << value << "-"  << endl;
   }

   splitter = next_eol + 2; 
 }
 
}

void PffNodeEMail::attributesTransportHeaders(Attributes* attr)
{
  size_t message_transport_headers_size  = 0; 
  uint8_t *entry_string = NULL;

  if (libpff_message_get_transport_headers_size(*(this->item), &message_transport_headers_size,
	          				     this->pff_error) != 1)
    return ;

  if (message_transport_headers_size <= 0)
    return ;

  entry_string =  new uint8_t [message_transport_headers_size];

//This read all in buff there no seems to have class to get each attributes could be written to a buffer node but here we will 
  if (libpff_message_get_transport_headers(*(this->item), entry_string, message_transport_headers_size, this->pff_error ) != 1 )
  {
    delete entry_string;
    return ;
  }
  this->splitTextToAttributes(std::string((char *)entry_string), attr);

  delete entry_string;
}


void PffNodeEMail::attributesRecipients(Attributes* attr)
{
  libpff_item_t	*recipients			= NULL;
  uint8_t 	*entry_value_string          	= NULL;
  int 		number_of_recipients		= 0;
  //int 		result				= 0;
  size_t 	entry_value_string_size         = 0;
  size_t 	maximum_entry_value_string_size = 0;
  uint32_t 	entry_value_32bit		= 0;
  int 		recipient_iterator		= 0;

//XXX fix me unicode doit display de l unicode ds les variant pas fait pour 
// soit just afficher les variant en string8 (coter python /qt) ou utiliser wchar_t ? + python qt
// autre probleme on fait un for pour les differents recipients ex: mail inbox 000007 il y en a 
// seulement le dernier apparait car les attributs on le meme nom donc ca doit ecraser....
// faire des liste et sous liste genre recipient1 : ... recipient2: /// -> refactor

  if (libpff_message_get_recipients(*(this->item), &recipients, this->pff_error) == 1)
  {
     if (libpff_item_get_number_of_sets(recipients, (uint32_t*) &number_of_recipients, this->pff_error) != 1)
      return ; 
     if (number_of_recipients > 0)
     {
	//XXX export_item_values -> pas fait mais peut etre a faire 
        //ici on imite export_hande_export_recipients_to_stream en attrib/variant
   	//6913
        for (recipient_iterator = 0; recipient_iterator < number_of_recipients; recipient_iterator++)
	{
	   if (libpff_item_get_entry_value_utf8_string_size(recipients, recipient_iterator, LIBPFF_ENTRY_TYPE_DISPLAY_NAME, &entry_value_string_size, 0, NULL) == 1)
	   {
	     if (entry_value_string_size > maximum_entry_value_string_size)
	     {
		maximum_entry_value_string_size = entry_value_string_size;
	     }
  	   }
	   if (libpff_recipients_get_display_name_size(recipients, recipient_iterator, &entry_value_string_size, NULL) == 1)
	   {
	      if (entry_value_string_size > maximum_entry_value_string_size)
		maximum_entry_value_string_size = entry_value_string_size;
	   }
	   if (libpff_item_get_entry_value_utf8_string_size(recipients, recipient_iterator, LIBPFF_ENTRY_TYPE_ADDRESS_TYPE, &entry_value_string_size, 0, NULL) == 1)
	   {
	      if (entry_value_string_size > maximum_entry_value_string_size)
		maximum_entry_value_string_size = entry_value_string_size;
	   }
           if (libpff_item_get_entry_value_utf8_string_size(recipients, recipient_iterator, LIBPFF_ENTRY_TYPE_EMAIL_ADDRESS, &entry_value_string_size, 0, NULL) == 1)
	   {	
	      if (entry_value_string_size > maximum_entry_value_string_size)
		maximum_entry_value_string_size = entry_value_string_size;
           }
	   if ((maximum_entry_value_string_size == 0))
		return ; //break ? 
	   entry_value_string = (uint8_t*) new uint8_t[maximum_entry_value_string_size];



	   if (libpff_item_get_entry_value_utf8_string(recipients, recipient_iterator, LIBPFF_ENTRY_TYPE_DISPLAY_NAME, entry_value_string, maximum_entry_value_string_size, 0, NULL) == 1)
	    (*attr)["Display Name"] = new Variant(std::string((char *)entry_value_string));

	   if (libpff_recipients_get_display_name(recipients, recipient_iterator, entry_value_string, maximum_entry_value_string_size, NULL) == 1)
	     (*attr)["Recipient display name"] = new Variant(std::string((char*)entry_value_string));

	   if (libpff_item_get_entry_value_utf8_string(recipients, recipient_iterator, LIBPFF_ENTRY_TYPE_ADDRESS_TYPE, entry_value_string, maximum_entry_value_string_size, 0, NULL) == 1)
	     (*attr)["Address type"] = new Variant((char*) entry_value_string);

	   if (libpff_item_get_entry_value_utf8_string(recipients, recipient_iterator, LIBPFF_ENTRY_TYPE_EMAIL_ADDRESS, entry_value_string, maximum_entry_value_string_size, 0, NULL) == 1)
	     (*attr)["Email address"] = new Variant((char*)entry_value_string);

	   if (libpff_recipients_get_type(recipients, recipient_iterator, &entry_value_32bit, NULL) == 1)
	   {
	      for (uint32_t n = 0; n < 5; n++)
	      {
		 if (n == 5)
	         {
		   (*attr)["Recipient type"] = new Variant(std::string("Unknown"));
		 }
		 if (entry_value_32bit == LIBPFF_RECIPIENT_TYPE[n].type)
		 {
		   (*attr)["Recipient type"] = new Variant(std::string(LIBPFF_RECIPIENT_TYPE[n].message));
		   break;
		 }
	      }
	   }
	   delete entry_value_string; //here seems ok ?  
	}	
	
     }	 
  }
}


void PffNodeEMail::attributesMessageConversationIndex(Attributes* attr)
{
//  cout << "Message conversation" << endl;//Conversation index.txt
//4953
/*
  uint8_t 	*entry_value		= NULL;
  uint8_t 	*entry_value_pointer	= NULL;
  size_t 	entry_value_size	= 0;
  uint64_t 	entry_value_64bit	= 0;
  uint32_t 	entry_value_iterator	= 0;
  int 		list_iterator		= 0;
  int	 	result			= 0;

  if (!(libpff_message_get_conversation_index_size(*(this->item), &entry_value_size, this->pff_error)))
	return;
  if (entry_value_size > 0)
  {
     entry_value = (uint8_t *) new uint8_t[entry_value_size];
     result = libpff_message_get_conversation_index(*(this->item), entry_value, entry_value_size, this->pff_error);
     if (result == -1)
       return ;
     else if (result != 0)
     {
        if (entry_value_size >= 22)
        {
	   if (entry_value[0] == 0x01)
           {
              filetime_buffer[ 0 ] = 0;
	      filetime_buffer[ 1 ] = 0;
	      filetime_buffer[ 2 ] = entry_value[ 5 ];
	      filetime_buffer[ 3 ] = entry_value[ 4 ];
	      filetime_buffer[ 4 ] = entry_value[ 3 ];
	      filetime_buffer[ 5 ] = entry_value[ 2 ];
	      filetime_buffer[ 6 ] = entry_value[ 1 ];
	      filetime_buffer[ 7 ] = entry_value[ 0 ];



           }
	}    
     }
  }
 */ 
}

void PffNodeEMail::attributesMessageHeader(Attributes* attr)
{
  char*				entry_value_string 		= NULL;
  size_t			entry_value_string_size 	= 0;
  size_t 			maximum_entry_value_string_size	= 0;
  uint64_t 			entry_value_64bit 		= 0;
  uint32_t 			entry_value_32bit 		= 0;
  uint8_t 			entry_value_boolean 		= 0;
  int 				result 				= 0;

//OUTLOOKMESSAGE.HEADERS TEXT -> Refacto sous formes de list est sous list !!
// virer ERROR si pas besoin et le mettre a NULL tous le temps...
//  libpff_file_get_item_by_identifier();
  maximum_entry_value_string_size = 24;

  check_maximum_size(libpff_item_get_display_name_size)
  check_maximum_size(libpff_message_get_conversation_topic_size)
  check_maximum_size(libpff_message_get_subject_size)
  check_maximum_size(libpff_message_get_sender_name_size)
  check_maximum_size(libpff_message_get_sender_email_address_size)

  if (!(maximum_entry_value_string_size))
    return ; 

  entry_value_string = (char *) new char[maximum_entry_value_string_size];

  value_time_to_attribute(libpff_message_get_client_submit_time, "Client submit time") 
  value_time_to_attribute(libpff_message_get_delivery_time, "Delivery time")
  value_time_to_attribute(libpff_message_get_creation_time, "Creation time")
  value_time_to_attribute(libpff_message_get_modification_time, "Modification time")
//3340 XXX libpff_message_get_size -> file size !! ??? message size ? set attr ou set as file size ?
  value_uint32_to_attribute(libpff_message_get_size, "Message size")  

  if (libpff_message_get_flags(*(this->item), &entry_value_32bit, NULL) == 1)
  {
     if ((entry_value_32bit & LIBPFF_MESSAGE_FLAG_READ) == LIBPFF_MESSAGE_FLAG_READ)
       (*attr)["is readed"] = new Variant(std::string("Yes"));
     else
       (*attr)["is readed"] = new Variant(std::string("No"));
     for (uint32_t n = 0; n < 9; n ++)
	if ((entry_value_32bit & LIBPFF_MESSAGE_FLAG[n].type) == LIBPFF_MESSAGE_FLAG[n].type)
	  (*attr)["flags"] = new Variant(std::string(LIBPFF_MESSAGE_FLAG[n].message));
	  //XXX flags REFACTO sous formes de list ! ???  //les var sont telle bien delete par python ?   
  }

  value_string_to_attribute(libpff_item_get_display_name, "Display name")
  value_string_to_attribute(libpff_message_get_conversation_topic, "Conversation topic") 
  value_string_to_attribute(libpff_message_get_subject, "Subject")
  value_string_to_attribute(libpff_message_get_sender_name, "Sender name")
  value_string_to_attribute(libpff_message_get_sender_email_address, "Sender email address")

  if (libpff_message_get_importance(*(this->item), &entry_value_32bit, NULL) == 1)
  {
     for (uint32_t n = 0; n < 3; n++)
       if (entry_value_32bit == LIBPFF_MESSAGE_IMPORTANCE_TYPE[n].type)
       {
	 (*attr)["Importance"] = new Variant(std::string(LIBPFF_MESSAGE_IMPORTANCE_TYPE[n].message)); 
	 break;
       }
  }

  if (libpff_message_get_priority(*(this->item), &entry_value_32bit, NULL) == 1)
  {
     for (uint32_t n = 0; n < 3; n++)
       if (entry_value_32bit == LIBPFF_MESSAGE_PRIORITY_TYPE[n].type)
       {
	 (*attr)["Priority"] = new Variant(std::string(LIBPFF_MESSAGE_PRIORITY_TYPE[n].message)); 
	 break;
       }
  }

  if (libpff_message_get_sensitivity(*(this->item), &entry_value_32bit, NULL) == 1)
  {
     for (uint32_t n = 0; n < 4; n++)
       if (entry_value_32bit == LIBPFF_MESSAGE_SENSITIVITY_TYPE[n].type)
       {
	 (*attr)["Sensitivity"] = new Variant(std::string(LIBPFF_MESSAGE_SENSITIVITY_TYPE[n].message));
	 break;
       }
  }

  if (libpff_message_get_is_reminder(*(this->item), &entry_value_boolean, NULL) == 1)
  {
    if (!(entry_value_boolean))
      (*attr)["Is a reminder"] = new Variant(std::string("no"));
    else
      (*attr)["Is a reminder"] = new Variant(std::string("yes"));
  }
  
  value_time_to_attribute(libpff_message_get_reminder_time, "Reminder time")
  value_time_to_attribute(libpff_message_get_reminder_signal_time, "Reminder signal time")

  if (libpff_message_get_is_private(*(this->item), &entry_value_boolean, NULL) == 1)
  {
    if (!(entry_value_boolean))
      (*attr)["Is private"] = new Variant(std::string("no"));
    else
      (*attr)["Is private"] = new Variant(std::string("yes"));	 
  }

  delete entry_value_string; 
}
