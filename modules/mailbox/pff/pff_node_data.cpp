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

PffNodeData::PffNodeData(std::string name, Node* parent, fso* fsobj, libpff_item_t *item_data, libpff_error_t** error) : Node(name, 0, parent, fsobj)
  
{
  this->item = new libpff_item_t *;
  *this->item = NULL;
  libpff_item_clone(this->item, item_data, error); //get identifier will use less memory but slower?
  this->setFile();
  this->pff_error = error;
}

fdinfo* PffNodeData::vopen(void)
{
  return (NULL);
}

int32_t PffNodeData::vread(fdinfo* fi, void *buff, unsigned int size)
{
  return (0);
}

int32_t PffNodeData::vclose(fdinfo* fi)
{
 return (-1);
}

uint64_t PffNodeData::vseek(fdinfo* fd, uint64_t offset, int whence)
{
  return (0);
}


