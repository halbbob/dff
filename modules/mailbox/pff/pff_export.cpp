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

/*
int pff:export_activity(libpff_item_t* item, int item_index)
{
      
}
*/


void pff::export_sub_items(libpff_item_t *item, Node* parent)
{
  libpff_item_t *sub_item = NULL;
  int 		number_of_sub_items = 0;
  int 		sub_item_iterator   = 0;

  //cout << "exporting sub items" << endl;
  if (libpff_item_get_number_of_sub_items(item, &number_of_sub_items, &(this->pff_error)) != 1)
    throw vfsError(std::string("Unable to retrive number of sub items."));

  for (sub_item_iterator = 0; sub_item_iterator < number_of_sub_items; sub_item_iterator++)
  {
    //XXX if export_handle->abort ?? arrete la bouclr ?
    //mimic export_handle_export_item


    if (libpff_item_get_sub_item(item, sub_item_iterator, &sub_item, &(this->pff_error)) != 1)
      throw vfsError(std::string("Unable to retrieve sub item."));
    //export_handle_export_item
    this->export_item(sub_item, sub_item_iterator, number_of_sub_items, parent);
    if (libpff_item_free(&sub_item, &(this->pff_error)) != 1)
      throw vfsError(std::string("Unable to free sub item.")); //xxx peut etre catch plus bas
  } 
  
}

int pff::export_item(libpff_item_t* item, int item_index, int number_of_items, Node* parent)
{
  uint8_t 	item_type		= 0;
  int 		result			= 0;

  //cout << "exorting item " << endl;
  if (libpff_item_get_type(item, &item_type, &(this->pff_error)) != 1)
    throw vfsError(std::string("Unable to retrive item type")); //catch + haut ?
  //switch export_handle 1918
  if (item_type == LIBPFF_ITEM_TYPE_ACTIVITY)
  {
	  cout << "Exporting activity" << endl;	
   // this->export_activity(item, item_index);
	//HEU THIS IS CALL !
   //result = this->export_activity(item, item_index, parent);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_APPOINTMENT)
  {
     result = this->export_appointment(item, item_index, parent);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_CONTACT)
  {
	  cout << "Exporting contact" << endl;
	  result = this->export_contact(item, item_index, parent);
	//  result = 1; //XXX for test de toute c  nimpos	
   // this->export_activity(item, item_index);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_DOCUMENT)
  {
	  cout << "Exporting document" << endl;	
   // this->export_activity(item, item_index);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_CONFLICT_MESSAGE || item_type == LIBPFF_ITEM_TYPE_EMAIL || item_type == LIBPFF_ITEM_TYPE_EMAIL_SMIME)
  {
//	  cout << "Exporting e-mail" << endl;	
     result = this->export_email(item, item_index, parent);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_FOLDER)
  {
	  //cout << "Exporting folder" << endl;	
    result = this->export_folder(item, item_index, parent);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_MEETING)
  {
	  cout << "Exporting meeting" << endl;	
   // this->export_activity(item, item_index);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_NOTE)
  {
	  cout << "Exporting note" << endl;	
   // this->export_activity(item, item_index);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_RSS_FEED)
  {
	  cout << "Exporting rss feed" << endl;	
   // this->export_activity(item, item_index);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_TASK)
  {
	  cout << "Exporting task" << endl;	
   // this->export_activity(item, item_index);
  }
  else
  {
	cout << "Exporting unknown type" << endl;
	result = 1; //XXX
  }
//return (1);
 return (result); //FIX ME c tous pouyris si on pecho pas un type d item tous s arrette ...
 //if result ...
}

int pff::export_contact(libpff_item_t* contact, int contact_index, Node* parent)
{
// 8920  export_handle_export_contact
  std::ostringstream contactName;

  contactName << std::string("Contact") << contact_index + 1;
  PffNodeFolder* nodeFolder = new PffNodeFolder(contactName.str(), parent, this);

  PffNodeContact*  nodeContact = new PffNodeContact(std::string("Contact"), nodeFolder, this, contact, &(this->pff_error));

  this->export_attachments(contact, nodeFolder);

  return (1);
}

int pff::export_appointment(libpff_item_t* appointment, int appointment_index, Node* parent)
{
   std::ostringstream messageName; 

   messageName << std::string("Appointment")  << appointment_index + 1; //start a 1 not 0
   PffNodeFolder* nodeFolder = new PffNodeFolder(messageName.str(), parent, this);


   PffNodeAppointment* 	nodeAppointment = new PffNodeAppointment(std::string("Appointment"), nodeFolder, this, appointment, &(this->pff_error), &(this->pff_file));

//export_handle_export_message_header_to_stream -> 8236 == a ce ki est ds un mail a recuperer ! creation de node mais surtout des metadata car rien dedans ! 

//export recipients  _> pareille que e-mail
// juste pas l air d export les transport header et c ds node e-mail par default !!

  this->export_attachments(appointment, nodeFolder);

  return (1);
}



int pff::export_activity(libpff_item_t* activity, int activity_index, Node* parent)
{
   return (1);
}

int pff::export_folder(libpff_item_t* folder, int folder_index, Node* parent)
{
  uint8_t 	*folder_name		= NULL;
  size_t 	folder_name_size	= 0;
  int 		result			= 0;
  //std::string	str_folder_name;

  //cout << "export_folder(item , " << folder_index << ");" << endl;
  if (libpff_folder_get_name_size(folder, &folder_name_size, &(this->pff_error)) == 1)
  {
   //  if (folder_name_size > (size_t) SSIZE_MAX)
     //  throw vfsError(std::string("folder name too long"));//catch avant
  }
  if (folder_name_size < 12)
    folder_name_size = 12;
  
  folder_name = (uint8_t *) new uint8_t[folder_name_size]; // (sizeof( uint8_t ) * folder_name_size );
  result = libpff_folder_get_name(folder, folder_name, folder_name_size, NULL);
//11394 export_handle.c 
//cout << folder_name << endl;
//XXX create node ?  
//XXX check folder name size et default to Folder%05

 // create_target_path(folder_name, folder_name_size, 
  PffNodeFolder *subFolder = new PffNodeFolder(std::string((char *)folder_name), parent, this);//wchar?

//  export_handle_make_directory
// 11585
// if export_handle->Dump_item_values -> ??? chelou c le modedebug cree un txt mais dump pas la meme chose que le else d apres, on commence par le else car il fait les subdir 
//11676
  if (export_sub_folders(folder, subFolder) != 1)
     throw vfsError(std::string("Unable to export sub folders")); //throw a catch ?
//XXX ici il faut continuer et creer les function sub_message et export_message ...
//  if (export_sub_messages(folder, target_path, target_path_size, preferred_export_format) != 1) 
  //  throw vfsError(std::string("Unable to export sub messages"));

  if (export_sub_messages(folder, subFolder) != 1)
    throw vfsError(std::string("Unable to export sub messages"));

  return (1);
}

int pff::export_email(libpff_item_t* email, int email_index, Node *parent)
{
//8888
  size_t 	email_html_body_size = 0;
  size_t 	email_rtf_body_size = 0;
  size_t 	email_text_body_size = 0;
  int 		has_html_body = 0;
  int 		has_rtf_body = 0;
  int 		has_text_body = 0;

 //if debug get identifier
//8965
//create_default_item_directory("Message", email_index) //cree une NodeDirectory -> message + email_index
//ex : Message00001
//puis met les data ds la directory donc soit on met le contenue de dans soit en arguments,
//mais penser au document joins car il faut les mettre dedans aussi ...

//if export-handle dump items alues // export_item_values
//check error 9031
  std::ostringstream messageName; 

  messageName << std::string("Message")  << email_index + 1; //start a 1 not 0

//  PffNodeFolder* nodeFolder = new PffNodeFolder(messageName.str(), parent, this);

  has_html_body = libpff_message_get_html_body_size(email, &email_html_body_size, &(this->pff_error));
  has_rtf_body = libpff_message_get_rtf_body_size(email, &email_rtf_body_size, &(this->pff_error));
  has_text_body = libpff_message_get_plain_text_body_size(email, &email_text_body_size, &(this->pff_error)); 
  
 //if format ==
  
  PffNodeFolder* nodeFolder = new PffNodeFolder(messageName.str(), parent, this);

  PffNodeEmailTransportHeaders* nodeTransportHeaders = new PffNodeEmailTransportHeaders("Transport Headers", nodeFolder, this, email, &(this->pff_error));

  if (has_text_body)
  {
	  //cout << "create text message node" << endl;
    PffNodeEmailMessageText* 	nodeMessageText = new PffNodeEmailMessageText("Message", nodeFolder, this, email, &(this->pff_error));
  }
  if (has_html_body)
  {
	  //cout << "create HTML message node" << endl;
    PffNodeEmailMessageHTML* 	nodeMessageHTML = new PffNodeEmailMessageHTML("Message HTML", nodeFolder, this, email, &(this->pff_error));
  }
  if (has_rtf_body)
  {
	  //cout << "create RTF message node" << endl;
    PffNodeEmailMessageRTF* 	nodeMessageRTF = new PffNodeEmailMessageRTF("Message RTF", nodeFolder, this, email, &(this->pff_error));
  }
//9361 Export Attachements
  this->export_attachments(email, nodeFolder);



  //simulate a  EXPORT_FORMAT_ALL // 9054
 //didn't do an export format FTK seems a binary reconstructed mode
 // != EXPORT_FORMAT_FTK

  return (1);
}

int pff::export_attachments(libpff_item_t* item, Node* parent)
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
 // result = libpff_message_get_attachments(item, &attachment, &(this->pff_error));
 // if (result == -1)
  //  return (-1);
//XXX intern struct info -> utiliser partout peu etre implanter ou en data directe ds le node en binaire 
  //else if (result == 1) //5894
   //  PffNodeItemValues*	pffNodeEmailItemValues = new PffNodeEmailItemValues("Item Value", nodeFolder, this, email, &(this->pff_error));
 
//5943 
  for (attachment_iterator = 0; attachment_iterator < number_of_attachments; attachment_iterator++)
  {
    libpff_item_t *attachment			= NULL;
     if (libpff_message_get_attachment(item, attachment_iterator, &attachment, &(this->pff_error)) != 1)
    {
	    //cout << "can t get attachment " << endl;
       continue ;
    }
     //cout << "attachment " << attachment_iterator << " get atchment ok " <<  endl;
    // new PffNodeAttachment();
     if (libpff_attachment_get_type(attachment, &attachment_type, &(this->pff_error)) != 1)
       continue;    

     //cout << "attachment " << attachment_iterator << " get type ok " <<  endl;
     if ((attachment_type != LIBPFF_ATTACHMENT_TYPE_DATA)
         && (attachment_type != LIBPFF_ATTACHMENT_TYPE_ITEM)
         && (attachment_type != LIBPFF_ATTACHMENT_TYPE_REFERENCE))
        continue;
 
     if ((attachment_type == LIBPFF_ATTACHMENT_TYPE_REFERENCE)) //6126
     {
	     //cout << "Attachment is stored externally" << endl;
       continue;
     }
     if (attachment_type == LIBPFF_ATTACHMENT_TYPE_DATA)
       libpff_attachment_get_long_filename_size(attachment, &attachment_filename_size,&(this->pff_error));

     attachment_filename = new uint8_t[attachment_filename_size];
    //6166
     if (attachment_filename == NULL)
       continue;
	
     //cout << "attachment " << attachment_iterator << " alloc filename ok " <<  endl;
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
//6255 create target path

//cout << "attachment " << attachment_iterator << " fileName ok " <<  endl;
//  6388
     //if attachent_type ...
     if (attachment_type == LIBPFF_ATTACHMENT_TYPE_DATA)
     {
	     //cout << "attachment type data " << endl;
	 result = libpff_attachment_get_data_size(attachment, &attachment_data_size, &(this->pff_error));
         if (result == -1)
	   continue;
         if ((result != 0) && (attachment_data_size > 0 ))
	 {
		//6443
		//cout << "create attachment " << endl;
	   new PffNodeAttachment(attachmentName.str(), parent, this, attachment, &(this->pff_error), attachment_data_size);
	 }
     }    
     else if(attachment_type == LIBPFF_ATTACHMENT_TYPE_ITEM)
     { //  6552 // 6808 function special ! 
	libpff_item_t**	attached_item = new libpff_item_t*;
	*attached_item = NULL;
	if (libpff_attachment_get_item(attachment, attached_item, &(this->pff_error)) == 1)
	{
	  PffNodeFolder* folder = new PffNodeFolder(attachmentName.str(), parent, this);		
          this->export_item(*attached_item, 0, 1, folder);
	 // libpff_item_free(attached_item, &(this->pff_error)); //didn't free because can't copy
	//delete atached_item
	}
	else
	{
	  delete attached_item;
	}
     }
  }
  return (1);
}

int pff::export_sub_folders(libpff_item_t* folder, PffNodeFolder* nodeFolder)
{
  libpff_item_t* sub_folder = NULL; 
  int 		number_of_sub_folders = 0;
  int 		sub_folder_iterator   = 0;

  //cout << "Exporting subitems folder" << endl;
  if (libpff_folder_get_number_of_sub_folders(folder, &number_of_sub_folders, &(this->pff_error)) != 1)
    throw vfsError(std::string("Unable to retrieve numbers of subfolders")); //catch plus haut
  for (sub_folder_iterator = 0; sub_folder_iterator < number_of_sub_folders; sub_folder_iterator++)
  {
     //abot return ?? 11812
     if (libpff_folder_get_sub_folder(folder, sub_folder_iterator, &sub_folder, &(this->pff_error)) != 1)
       throw vfsError(std::string("Unable to retrieve sub folders"));
     if (export_folder(sub_folder, sub_folder_iterator, nodeFolder) != 1) //catch ici car recursif ? 
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

  //export_handle 11908
  //cout << "Exporting submessages" << endl;
  if (libpff_folder_get_number_of_sub_messages(folder, &number_of_sub_messages, &(this->pff_error)) != 1)
    throw vfsError(std::string("Unable to retrieve number of sub messages"));
  for (sub_message_iterator = 0; sub_message_iterator < number_of_sub_messages; sub_message_iterator++)
  {
      //export handle abort ...
     if (libpff_folder_get_sub_message(folder, sub_message_iterator, &sub_message, &(this->pff_error)) != 1)
       throw vfsError(std::string("Unable to retrieve sub message"));  
     if (export_item(sub_message, sub_message_iterator, number_of_sub_messages, nodeFolder) != 1)
       throw vfsError(std::string("Unable to export sub message"));
     if (libpff_item_free(&sub_message, &(this->pff_error)) != 1)
       throw vfsError("Unable to free sub message");
  }

  return (1);
}


