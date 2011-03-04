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



PffNodeAttachment::PffNodeAttachment(std::string name, Node* parent, fso* fsobj, libpff_item_t *mail, libpff_error_t** error, size64_t size) : PffNodeEMail(name, parent, fsobj, mail, error)
{
  this->setSize(size); 
}


uint8_t*	PffNodeAttachment::dataBuffer(void)
{
  uint8_t*	buff = NULL;
  
  if (this->size() <= 0)
    return (NULL);
  
  buff =  new uint8_t[this->size()];
  
  //6490
  //uint32_t read_count                         = 0;
  uint8_t *attachment_data                   = NULL;
  size64_t attachment_data_size              = 0;
  uint32_t total_read			     = 0;
  //off64_t result			     = 0;
  //off64_t rsize				     = 0;

  ssize_t read_count                         = 0;
  size_t read_size                           = 0;

  if (libpff_attachment_data_seek_offset(*(this->item), 0, SEEK_SET, this->pff_error) != 0)
    return (NULL); //XXX can't be concurrent no FD in libpff !!! ? or maybe clone item here
  
  read_count = libpff_attachment_data_read_buffer(*(this->item), (uint8_t*)buff , this->size(), this->pff_error);
  //cout << "create buff size " << endl;
  return buff;
  // WORK BUT SEEK DONT WORK AFTER 8192KO this is in the bugtracker == 1 item size, look if a patch is possible
  ////read 8192 max
  //attachment_data_size = this->size();
  //while (attachment_data_size > 0)
  //{ 
  //if (attachment_data_size > 8192)
  //read_size  = 8192;
  //else
  //read_size = attachment_data_size;
  //attachment_data_size -= read_size;
  ////cout << " total read " << total_read << endl;
  ////cout << "seek set " << libpff_attachment_data_seek_offset(*(this->item), total_read, SEEK_SET, this->pff_error) << endl;
  //read_count = libpff_attachment_data_read_buffer(*(this->item), (uint8_t*)buff + total_read, read_size, this->pff_error);
  //
  //total_read += read_count;
  ////cout << "attachmen read rsize " << read_size << "read count " << read_count << endl;
  //if (read_count != (ssize_t) read_size)
  //{
  ////cout << "attachment finally read " << this->size() - attachment_data_size << endl;
  //return (NULL); //vfs error
  //}
  //}
  //cout << "attachment finally read " << this->size() - attachment_data_size << endl;
  //return (buff);
}

//PffNodeAttachment::PffNodeAttachment(std::string name, Node* parent, fso* fsobj, libpff_item_t *item, libpff_error_t** error, size64_t size) : PffNodeData(name, parent, fsobj, item, error) //format HTML / TXT  / RTF
//{
  //this->setSize(size);
//}



//fdinfo* PffNodeAttachment::vopen(void)
//{
   //fdinfo*		fi;
   //uint8_t*		buff;

   //cout << "attachment::vopen " << endl;
   //cout << "vopen vseek 0 "<< libpff_attachment_data_seek_offset(*(this->item), 0, SEEK_SET, this->pff_error) << endl;

   //cout << "vopen vseek 2048 "<< libpff_attachment_data_seek_offset(*(this->item), 2048, SEEK_SET, this->pff_error) << endl;
   //cout << "vopen vseek 8192 "<< libpff_attachment_data_seek_offset(*(this->item), 8192, SEEK_SET, this->pff_error) << endl;
   //cout << "vopen vseek 12288 "<< libpff_attachment_data_seek_offset(*(this->item), 12288, SEEK_SET, this->pff_error) << endl;
   //cout << "vopen vseek 10000 "<< libpff_attachment_data_seek_offset(*(this->item), 10000, SEEK_SET, this->pff_error) << endl;
   //fi = new fdinfo;
////   buff = this->dataBuffer();
  //// if (buff == NULL)
    //// return (NULL);

   ////fi->fm = (FileMapping*) (buff);
  //if (libpff_attachment_data_seek_offset(*(this->item), 0, SEEK_SET, this->pff_error) != 0 )
    //return(NULL);

////  attachment_data = (uint8_t *) new uint8_t[EXPORT_HANDLE_BUFFER_SIZE];

   //fi->node = this;
   //fi->offset = 0;
   //return (fi);
//}

//int32_t  PffNodeAttachment::vread(fdinfo* fi, void *buff, unsigned int size)
//{
////6490
  //uint32_t read_count                         = 0;
  //uint8_t *attachment_data                   = NULL;
  //off64_t result			     = 0;
  //off64_t rsize				     = 0;

  //cout << "attachement::vread fi->offset " << fi->offset << endl;
////  result = libpff_attachment_data_seek_offset(*(this->item), (off64_t)fi->offset, SEEK_SET, this->pff_error);

  ////if (result != fi->offset)  
  ////{
    ////cout << "attachment::vread return 0 result " << result << " fi offset " << fi->offset << endl;
	////return (0); //XXX can't be concurrent no FD in libpff !!! ? or maybe clone item here
  ////}
////read 8192 max
//cout << "while " << size << endl;
  //while (read_count < size)
  //{ 
    //if (size > 8192)
      //rsize  = 8192;
    //else
      //rsize = size;
    //result= libpff_attachment_data_read_buffer(*(this->item),( (uint8_t*)buff + read_count), rsize, this->pff_error);
           
    //cout << "attachment::vread rsize " << rsize << endl;
    //if (result != (ssize_t) rsize)
    //{
      //cout << "Attachment::Vread return " << result << " != " << read_count << endl;
      //if (result !=  (off64_t)-1)
      //{
        //fi->offset += result;
	//read_count += result;
      //}
      //return (read_count); //vfs error
    //}
    //fi->offset += result;
    //read_count += result;
  //}
  //return (read_count);
//}

//uint64_t	PffNodeAttachment::vseek(fdinfo *fi, uint64_t offset, int whence)
//{
  //off64_t 	result;

  //cout << "attachment::vseek offset " << offset <<  " whence " << whence <<  " fi-offset " << fi->offset <<  endl;
  //result = libpff_attachment_data_seek_offset(*(this->item), offset, whence, this->pff_error);
  //if (result == (uint64_t) -1)
  //{
   //cout << "vseek - 1" << endl;
    //return result;
  //}

  //cout << "attachment::vseek result " << result  << endl;
  //fi->offset = result;
  //cout << "attachment::vseek done " << fi->offset  << endl;
  //return fi->offset;
//}

//int32_t PffNodeAttachment::vclose(fdinfo *fi)
//{
  //cout << "close " << endl;
  //if (libpff_attachment_data_seek_offset(*(this->item), 0, SEEK_SET, this->pff_error) != 0 )
    //return(0);
  //return (1);
//}


