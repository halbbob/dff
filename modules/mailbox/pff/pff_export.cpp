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

#include <sstream>
#include "pff.hpp"

void pff::export_sub_items(libpff_item_t *item, Node* parent)
{
  libpff_item_t *sub_item = NULL;
  int 		number_of_sub_items = 0;
  int 		sub_item_iterator   = 0;

  if (libpff_item_get_number_of_sub_items(item, &number_of_sub_items, &(this->pff_error)) != 1)
    throw vfsError(std::string("Unable to retrive number of sub items."));

  for (sub_item_iterator = 0; sub_item_iterator < number_of_sub_items; sub_item_iterator++)
  {
    if (libpff_item_get_sub_item(item, sub_item_iterator, &sub_item, &(this->pff_error)) != 1)
      throw vfsError(std::string("Unable to retrieve sub item."));
    this->export_item(sub_item, sub_item_iterator, number_of_sub_items, parent);
    if (libpff_item_free(&sub_item, &(this->pff_error)) != 1)
      throw vfsError(std::string("Unable to free sub item."));
  } 
  
}

int pff::export_item(libpff_item_t* item, int item_index, int number_of_items, Node* parent, bool clone)
{
  uint8_t 	item_type		= 0;
  int 		result			= 0;

  if (libpff_item_get_type(item, &item_type, &(this->pff_error)) != 1)
    throw vfsError(std::string("Unable to retrive item type"));
  if (item_type == LIBPFF_ITEM_TYPE_ACTIVITY)
  {
    cout << "Exporting activity" << endl;	
  }
  else if (item_type == LIBPFF_ITEM_TYPE_APPOINTMENT)
  {
    result = this->export_appointment(item, item_index, parent, clone);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_CONTACT)
  {
    result = this->export_contact(item, item_index, parent, clone);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_DOCUMENT)
  {
    cout << "Exporting document" << endl;	
  }
  else if (item_type == LIBPFF_ITEM_TYPE_CONFLICT_MESSAGE || item_type == LIBPFF_ITEM_TYPE_EMAIL || item_type == LIBPFF_ITEM_TYPE_EMAIL_SMIME)
  {
    result = this->export_email(item, item_index, parent, clone);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_FOLDER)
  {
    result = this->export_folder(item, item_index, parent, clone);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_MEETING)
  {
    result = this->export_meeting(item, item_index, parent, clone); 
  }
  else if (item_type == LIBPFF_ITEM_TYPE_NOTE)
  {
    cout << "Exporting note" << endl;
    //XXX code me 
    result = 1;	
  }
  else if (item_type == LIBPFF_ITEM_TYPE_RSS_FEED)
  {
    cout << "Exporting rss feed" << endl;
  }
  else if (item_type == LIBPFF_ITEM_TYPE_TASK)
  {
    result = this->export_task(item, item_index, parent, clone);
  }
  else
  {
    cout << "Exporting unknown type" << endl; //add->result[error]... XXX
    result = 1;
  }
//return (1);
 return (result); //FIXME must return 1 and set add->result according to error
}

int pff::export_meeting(libpff_item_t* meeting, int meeting_index, Node* parent, bool clone)
{
  std::ostringstream meetingName;

  meetingName << std::string("Meeting") << meeting_index + 1;
  PffNodeFolder* nodeFolder = new PffNodeFolder(meetingName.str(), parent, this);

  new PffNodeMeeting(std::string("Meeting"), nodeFolder, this, meeting, &(this->pff_error), &(this->pff_file), clone);

  return (1);
}

int pff::export_task(libpff_item_t* task, int task_index, Node* parent, bool clone)
{
  std::ostringstream taskName;

  taskName << std::string("Task") << task_index + 1;
  PffNodeFolder* nodeFolder = new PffNodeFolder(taskName.str(), parent, this);

  new PffNodeTask(std::string("Task"), nodeFolder, this, task, &(this->pff_error), &(this->pff_file), clone);

  this->export_attachments(task, nodeFolder, clone);

  return (1);
}


int pff::export_contact(libpff_item_t* contact, int contact_index, Node* parent, bool clone)
{
  std::ostringstream contactName;

  contactName << std::string("Contact") << contact_index + 1;
  PffNodeFolder* nodeFolder = new PffNodeFolder(contactName.str(), parent, this);

  new PffNodeContact(std::string("Contact"), nodeFolder, this, contact, &(this->pff_error), &(this->pff_file), clone);

  this->export_attachments(contact, nodeFolder, clone);

  return (1);
}

int pff::export_appointment(libpff_item_t* appointment, int appointment_index, Node* parent, bool clone)
{
   std::ostringstream messageName; 

   messageName << std::string("Appointment")  << appointment_index + 1;
   PffNodeFolder* nodeFolder = new PffNodeFolder(messageName.str(), parent, this);

   new PffNodeAppointment(std::string("Appointment"), nodeFolder, this, appointment, &(this->pff_error), &(this->pff_file), clone);

  this->export_attachments(appointment, nodeFolder, clone);

  return (1);
}



int pff::export_activity(libpff_item_t* activity, int activity_index, Node* parent, bool clone)
{
   return (1);
}

int pff::export_folder(libpff_item_t* folder, int folder_index, Node* parent, bool clone)
{
  uint8_t 	*folder_name		= NULL;
  size_t 	folder_name_size	= 0;
  int 		result			= 0;

  if (libpff_folder_get_name_size(folder, &folder_name_size, &(this->pff_error)) == 1)
  {
    //XXX != 0 && != -1
   //  if (folder_name_size > (size_t) SSIZE_MAX)
     //  throw vfsError(std::string("folder name too long"));//catch avant
  }
  if (folder_name_size < 12)
    folder_name_size = 12;
  
  folder_name = (uint8_t *) new uint8_t[folder_name_size];
  result = libpff_folder_get_name(folder, folder_name, folder_name_size, NULL);
  PffNodeFolder *subFolder = new PffNodeFolder(std::string((char *)folder_name), parent, this);

  if (export_sub_folders(folder, subFolder) != 1)
     throw vfsError(std::string("Unable to export sub folders"));
  if (export_sub_messages(folder, subFolder) != 1)
    throw vfsError(std::string("Unable to export sub messages"));

  return (1);
}

int pff::export_email(libpff_item_t* email, int email_index, Node *parent, bool clone)
{
  size_t 	email_html_body_size = 0;
  size_t 	email_rtf_body_size = 0;
  size_t 	email_text_body_size = 0;
  int 		has_html_body = 0;
  int 		has_rtf_body = 0;
  int 		has_text_body = 0;

  std::ostringstream messageName; 
  messageName << std::string("Message")  << email_index + 1;

  has_html_body = libpff_message_get_html_body_size(email, &email_html_body_size, &(this->pff_error));
  has_rtf_body = libpff_message_get_rtf_body_size(email, &email_rtf_body_size, &(this->pff_error));
  has_text_body = libpff_message_get_plain_text_body_size(email, &email_text_body_size, &(this->pff_error)); 
  
  PffNodeFolder* nodeFolder = new PffNodeFolder(messageName.str(), parent, this);

  new PffNodeEmailTransportHeaders("Transport Headers", nodeFolder, this, email, &(this->pff_error), &(this->pff_file), clone);

  if (has_text_body)
  {
    new PffNodeEmailMessageText("Message", nodeFolder, this, email, &(this->pff_error), &(this->pff_file), clone);
  }
  if (has_html_body)
  {
    new PffNodeEmailMessageHTML("Message HTML", nodeFolder, this, email, &(this->pff_error), &(this->pff_file), clone);
  }
  if (has_rtf_body)
  {
    new PffNodeEmailMessageRTF("Message RTF", nodeFolder, this, email, &(this->pff_error), &(this->pff_file), clone);
  }

  this->export_attachments(email, nodeFolder, clone);
 //didn't do an export format FTK seems a binary reconstructed mode
 // != EXPORT_FORMAT_FTK

  return (1);
}

int pff::export_attachments(libpff_item_t* item, Node* parent, bool clone)
{
  int		result 				= 0;
  int 		attachment_type         	= 0;
  int 		attachment_iterator     	= 0;
  int 		number_of_attachments   	= 0;
  size_t 	attachment_filename_size	= 0;
  size64_t 	attachment_data_size            = 0;
  uint8_t*	attachment_filename     	= NULL;

  if (libpff_message_get_number_of_attachments(item, &number_of_attachments, &(this->pff_error) ) != 1 )
    return (-1);
  if (number_of_attachments <= 0)
    return (-1);
 
  for (attachment_iterator = 0; attachment_iterator < number_of_attachments; attachment_iterator++)
  {
    libpff_item_t *attachment			= NULL;
     if (libpff_message_get_attachment(item, attachment_iterator, &attachment, &(this->pff_error)) != 1)
     {
       continue ;
     }
     if (libpff_attachment_get_type(attachment, &attachment_type, &(this->pff_error)) != 1)
     {
       libpff_item_free(&attachment, &(this->pff_error));
       continue;    
     }
     if ((attachment_type != LIBPFF_ATTACHMENT_TYPE_DATA)
         && (attachment_type != LIBPFF_ATTACHMENT_TYPE_ITEM)
         && (attachment_type != LIBPFF_ATTACHMENT_TYPE_REFERENCE))
     {
	libpff_item_free(&attachment, &(this->pff_error));
        continue;
     }
     if ((attachment_type == LIBPFF_ATTACHMENT_TYPE_REFERENCE))
     {
       libpff_item_free(&attachment, &(this->pff_error));
       continue;
     }
     if (attachment_type == LIBPFF_ATTACHMENT_TYPE_DATA)
       libpff_attachment_get_long_filename_size(attachment, &attachment_filename_size,&(this->pff_error));

     attachment_filename = new uint8_t[attachment_filename_size];
     if (attachment_filename == NULL)
     {
       libpff_item_free(&attachment, &(this->pff_error));
       delete attachment_filename;
       continue;
     }	
     std::ostringstream attachmentName;
     if (attachment_type == LIBPFF_ATTACHMENT_TYPE_DATA)
     {
       if ( libpff_attachment_get_long_filename(attachment, attachment_filename, attachment_filename_size, NULL ) != 1 )
  	 attachmentName << std::string("Attachment") << attachment_iterator + 1;
       else 
         attachmentName << std::string((char*)attachment_filename);
  
     }
     else if (attachment_type == LIBPFF_ATTACHMENT_TYPE_ITEM)
  	 attachmentName << std::string("Attachment") << attachment_iterator + 1;

     if (attachment_type == LIBPFF_ATTACHMENT_TYPE_DATA)
     {
	 result = libpff_attachment_get_data_size(attachment, &attachment_data_size, &(this->pff_error));
         if (result == -1)
	 {
	   libpff_item_free(&attachment, &(this->pff_error));
	   delete attachment_filename;
	   continue;
	 }
         if ((result != 0) && (attachment_data_size > 0 ))
	 {
	   new PffNodeAttachment(attachmentName.str(), parent, this, item, &(this->pff_error), attachment_data_size, &(this->pff_file), attachment_iterator, clone);
	   delete attachment_filename;
	   libpff_item_free(&attachment, &(this->pff_error));
	 }
     }    
     else if(attachment_type == LIBPFF_ATTACHMENT_TYPE_ITEM)
     {
	libpff_item_t**	attached_item = new libpff_item_t*;
	*attached_item = NULL;
	if (libpff_attachment_get_item(attachment, attached_item, &(this->pff_error)) == 1)
	{
          uint8_t	item_type;
	  PffNodeFolder* folder = new PffNodeFolder(attachmentName.str(), parent, this);		
          this->export_item(*attached_item, 0, 1, folder, true);
          if (libpff_item_get_type(item, &item_type, &(this->pff_error)) == 1)
            if (item_type != LIBPFF_ITEM_TYPE_APPOINTMENT)
	      libpff_item_free(attached_item, &(this->pff_error)); //didn't free because can't copy ->appointment
	}
	else
	{
	  delete attached_item;
	}
	libpff_item_free(&attachment, &(this->pff_error));
	delete attachment_filename;
     }
  }
  return (1);
}

int pff::export_sub_folders(libpff_item_t* folder, PffNodeFolder* nodeFolder)
{
  libpff_item_t* sub_folder = NULL; 
  int 		number_of_sub_folders = 0;
  int 		sub_folder_iterator   = 0;

  if (libpff_folder_get_number_of_sub_folders(folder, &number_of_sub_folders, &(this->pff_error)) != 1)
    throw vfsError(std::string("Unable to retrieve numbers of subfolders"));
  for (sub_folder_iterator = 0; sub_folder_iterator < number_of_sub_folders; sub_folder_iterator++)
  {
     if (libpff_folder_get_sub_folder(folder, sub_folder_iterator, &sub_folder, &(this->pff_error)) != 1)
       throw vfsError(std::string("Unable to retrieve sub folders"));
     if (export_folder(sub_folder, sub_folder_iterator, nodeFolder, false) != 1)
       throw vfsError(std::string("Unable to export sub folders"));  
     if (libpff_item_free(&sub_folder, &(this->pff_error)) != 1)
       throw vfsError(std::string("Unable to free sub folder")); 
  }
  return (1);
}

int pff::export_sub_messages(libpff_item_t* folder, PffNodeFolder* nodeFolder)
{
  libpff_item_t *sub_message = NULL; 
  int number_of_sub_messages = 0;
  int sub_message_iterator   = 0;

  if (libpff_folder_get_number_of_sub_messages(folder, &number_of_sub_messages, &(this->pff_error)) != 1)
    throw vfsError(std::string("Unable to retrieve number of sub messages"));
  for (sub_message_iterator = 0; sub_message_iterator < number_of_sub_messages; sub_message_iterator++)
  {
     if (libpff_folder_get_sub_message(folder, sub_message_iterator, &sub_message, &(this->pff_error)) != 1)
       throw vfsError(std::string("Unable to retrieve sub message"));  
     if (export_item(sub_message, sub_message_iterator, number_of_sub_messages, nodeFolder) != 1)
       throw vfsError(std::string("Unable to export sub message"));
     if (libpff_item_free(&sub_message, &(this->pff_error)) != 1)
       throw vfsError("Unable to free sub message");
  }

  return (1);
}
