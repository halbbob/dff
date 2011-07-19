/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal Jacob <sja@digital-forensic.org>
 */

#include "ewfnode.hpp"


std::string  ewf_properties[] = { 
                      "case_number", "description", "examinier_name",
                      "evidence_number", "notes", "acquiry_date",
                      "system_date", "acquiry_operating_system",
                      "acquiry_software_version", "password",
                      "compression_type", "model", "serial_number"
            };

Attributes	EWFNode::_attributes()
{
  Attributes 	attr;
  uint8_t*      buff = (uint8_t*)malloc(sizeof(uint8_t) * 1024);


  libewf_parse_header_values(this->ewfso->ewf_ghandle, 4); 
  for (int i = 0; i < 13; i++)
  {
     libewf_get_header_value(this->ewfso->ewf_ghandle, ewf_properties[i].c_str(), (char*)buff, 1024);
     attr[ewf_properties[i]] = new Variant(std::string((char*)buff));
  }
 
  if (libewf_get_md5_hash(this->ewfso->ewf_ghandle, buff, 16) == 1)
  {
    std::ostringstream  hexval;

    hexval << hex <<  bytes_swap64(*((uint64_t*)(buff))) << bytes_swap64(*((uint64_t*)(buff + 8))); 
    attr["md5"] = new Variant(hexval.str());
  }
  free(buff);

  return attr;
}


EWFNode::EWFNode(std::string Name, uint64_t size, Node* parent, ewf* fsobj, std::list<Variant*> origPath): Node(Name, size, parent, fsobj)
{
  this->originalPath = origPath;
  this->ewfso = fsobj;
}

EWFNode::~EWFNode()
{
}
