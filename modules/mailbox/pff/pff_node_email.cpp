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
// XXX delete this if ok whi PffNodeData

PffNodeEMail::PffNodeEMail(std::string name, Node* parent, fso* fsobj, libpff_error_t** error) :PffNodeData(name, parent, fsobj, error)
{
}



PffNodeEMail::PffNodeEMail(std::string name, Node* parent, fso* fsobj, libpff_item_t *item, libpff_error_t** error) : PffNodeData(name, parent, fsobj, item, error) //format HTML / TXT  / RTF
{
  //this->itemEMail = mail;
  //libpff_item_get_identifier(*mail, &(this->identifier), *error);
 
// 9335 export_handle_export_message_body
// 9361 export_handle_export_attachments
 //export message header 9147
//node buffer 
//exportMessageHtml
}

std::string	PffNodeEMail::icon(void)
{
  return (":mail_generic");
}


uint8_t*	PffNodeEMail::dataBuffer(void)
{
  return (NULL);
}

fdinfo* PffNodeEMail::vopen(void)
{
   fdinfo*				fi;
   uint8_t*				buff;

   fi = new fdinfo;
   buff = this->dataBuffer();
   if (buff == NULL)
     return (NULL);

   fi->fm = (FileMapping*) (buff);
   fi->node = this;
   fi->offset = 0;
   return (fi);
}

int32_t  PffNodeEMail::vread(fdinfo* fi, void *buff, unsigned int size)
{
  uint8_t*				rbuff;
  //uint32_t				readed;
 
  rbuff = (uint8_t*)fi->fm;

  if (fi->offset > this->size())
  {
    return (0);
  }
  if ((fi)->offset + size > this->size())
    size = this->size() - fi->offset;
  memcpy(buff, rbuff + (uint32_t)fi->offset, size);
  fi->offset += size; 
 
  //cout << "Vread size" << size << endl;
  return (size);
}

uint64_t	PffNodeEMail::vseek(fdinfo* fi, uint64_t offset, int whence)
{
	//cout << "pffNodeEMail::vseek offset " << offset << " whence " << whence << endl;	 
    if (whence == 0)
    {
      if (offset <= this->size())
      {
        fi->offset = offset;
        return (fi->offset);
      }
    }
    else if (whence == 1)
    {
      if (fi->offset + offset <= this->size())
      {
        fi->offset += offset;
        return (fi->offset);
      }
    }
    else if (whence == 2)
    {
      fi->offset = this->size();
      return (fi->offset);
    }
  return ((uint64_t) -1);
}


int32_t PffNodeEMail::vclose(fdinfo *fi)
{
  uint8_t*				rbuff;
  rbuff = (uint8_t*)fi->fm;
  delete rbuff;

  return (0);
}


