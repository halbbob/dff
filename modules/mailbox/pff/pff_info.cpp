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


libpff_macro_s LIBPFF_VALID_FOLDER_MASK[8] = 
{
    { LIBPFF_VALID_FOLDER_MASK_SUBTREE, "Subtree" },
    { LIBPFF_VALID_FOLDER_MASK_INBOX, "Inbox" },
    { LIBPFF_VALID_FOLDER_MASK_OUTBOX, "Outbox" },
    { LIBPFF_VALID_FOLDER_MASK_WASTEBOX, "Wastebox" },
    { LIBPFF_VALID_FOLDER_MASK_SENTMAIL, "Sentmail" },
    { LIBPFF_VALID_FOLDER_MASK_VIEWS, "Views" },
    { LIBPFF_VALID_FOLDER_MASK_COMMON_VIEWS, "Common views" },
    { LIBPFF_VALID_FOLDER_MASK_FINDER, "Finder" }
};
 


libpff_macro_s FILE_CONTENT_TYPE[3] = 
{
    { LIBPFF_FILE_CONTENT_TYPE_PAB, "Personal Address Book (PAB)" },
    { LIBPFF_FILE_CONTENT_TYPE_PST, "Personal Storage Tables (PST)" },
    { LIBPFF_FILE_CONTENT_TYPE_OST, "Offline Storage Tables (OST)" }
};


libpff_macro_s FILE_TYPE[2] =  
{
    { LIBPFF_FILE_TYPE_32BIT, "32-bit" },
    { LIBPFF_FILE_TYPE_64BIT, "64-bit" }
};
  
libpff_macro_s FILE_ENCRYPTION_TYPE[3] = 
{
    { LIBPFF_ENCRYPTION_TYPE_NONE, "none" },
    { LIBPFF_ENCRYPTION_TYPE_COMPRESSIBLE, "compressible" },
    { LIBPFF_ENCRYPTION_TYPE_HIGH, "high" }
}; 



void pff::info()
{
   this->info_file();
   this->info_message_store();
   this->info_unallocated_blocks();
}


void pff::info_file()
{
  size64_t	file_size	  = 0;
  uint8_t 	file_content_type = 0;
  uint8_t 	file_type         = 0;
  uint8_t 	encryption_type   = 0;


  if (libpff_file_get_size(this->pff_file, &file_size, &(this->pff_error)) != 1)
    throw vfsError(std::string("unable to retrieve size."));
  if (libpff_file_get_content_type(this->pff_file, &file_content_type, &(this->pff_error)) != 1)
    throw vfsError(std::string("unable to retrieve file content type."));
  if (libpff_file_get_type(this->pff_file, &file_type, &(this->pff_error)) != 1)
    throw vfsError(std::string("unable to retrieve file type."));
  if (libpff_file_get_encryption_type(this->pff_file, &encryption_type, &(this->pff_error)) != 1)
    throw vfsError(std::string("unable to retrieve encryption type."));
 
  std::string message = ""; 
  for (uint8_t n = 0;  n <  3; n++)
  {
    if (file_content_type == FILE_CONTENT_TYPE[n].type)
    {
      message = FILE_CONTENT_TYPE[n].message;
      break;
    }
  } 
  if (message != "") 
    cout << "file type content : " << message << endl;
  else
    cout << "file type content unknown" << file_type << endl;

  message = "";
  for (uint8_t n = 0;  n <  2; n++)
  {
    if (file_type == FILE_TYPE[n].type)
    {
      message = FILE_TYPE[n].message;
      break;
    }
  } 
  if (message != "") 
    cout << "file type : " << message << endl;
  else
    cout << "file type unknown" << file_type << endl;

 
  cout << "Encryption type:" << endl;
  message = "";
  for (uint8_t n = 0;  n <  3; n++)
  {
    if (encryption_type == FILE_ENCRYPTION_TYPE[n].type)
    {
      message = FILE_ENCRYPTION_TYPE[n].message;
      break;
    }
  } 
  if (message != "") 
    cout << "file encryption type : " << message << endl;
  else
    cout << "file encryption type unknown" << encryption_type << endl;

 
}




void pff::info_message_store()
{
  libpff_item_t *message_store = NULL;
  uint32_t 	password_checksum   = 0;
  uint32_t 	valid_folder_mask   = 0;


  if (libpff_file_get_message_store(this->pff_file, &message_store, &(this->pff_error)) == -1)
    throw vfsError(std::string("Unable to retrieve message store"));

  cout << "message store:" << endl; 
  if (libpff_message_store_get_valid_folder_mask(message_store, &valid_folder_mask, NULL) == 1)
  {
     for (uint8_t n = 0; n < 8 ; n++)
     {
       if ((valid_folder_mask & LIBPFF_VALID_FOLDER_MASK[n].type) == LIBPFF_VALID_FOLDER_MASK[n].type)
         cout << LIBPFF_VALID_FOLDER_MASK[n].message << endl;
     }
  }

  if (libpff_message_store_get_password_checksum(message_store, &password_checksum, NULL) == 1)
  {
     cout << "Password checksum" << endl;
     if (password_checksum == 0)
       cout << "N/A" << endl;
     else
       printf("0x%08x\n", password_checksum);
  }
  if (libpff_item_free(&message_store, &(this->pff_error)) != 1)
    throw vfsError(std::string("Unable to free message store item."));

  return;
}



void pff::info_unallocated_blocks()
{
  off64_t offset                   = 0;
  size64_t size                    = 0;
  int number_of_unallocated_blocks = 0;
  int block_iterator               = 0;

  if (libpff_file_get_number_of_unallocated_blocks(this->pff_file, LIBPFF_UNALLOCATED_BLOCK_TYPE_PAGE, &number_of_unallocated_blocks, &(this->pff_error)) != 1)
    throw vfsError(std::string("unable to retrieve number of unallocated page blocks."));
  cout << "Found " << number_of_unallocated_blocks << " unallocated page blocks" << endl;

  if (number_of_unallocated_blocks > 0)
  {
     for (block_iterator = 0; block_iterator < number_of_unallocated_blocks; block_iterator++)
     {
	if (libpff_file_get_unallocated_block(this->pff_file, LIBPFF_UNALLOCATED_BLOCK_TYPE_PAGE, block_iterator, &offset, &size, &(this->pff_error)) == 1)
	  printf("%016llx - %016llx size : %lld\n", offset, offset + size, size);	
     }
  }

 if (libpff_file_get_number_of_unallocated_blocks(this->pff_file, LIBPFF_UNALLOCATED_BLOCK_TYPE_DATA, &number_of_unallocated_blocks, &(this->pff_error)) != 1)
    throw vfsError(std::string("unable to retrieve number of unallocated data blocks."));
  cout << "Found " << number_of_unallocated_blocks << " unallocated data blocks" << endl;

  if (number_of_unallocated_blocks > 0)
  {
     for (block_iterator = 0; block_iterator < number_of_unallocated_blocks; block_iterator++)
     {
	if (libpff_file_get_unallocated_block(this->pff_file, LIBPFF_UNALLOCATED_BLOCK_TYPE_DATA, block_iterator, &offset, &size, &(this->pff_error)) == 1)
	  printf("%016llx - %016llx size : %lld\n", offset, offset + size, size);	
     }
  }

}

