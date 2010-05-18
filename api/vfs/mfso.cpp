/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include "mfso.hpp"

mfso::mfso(std::string name)
{
  this->name = name;
  this->res = new results(name);
  //this->root = new Node(NULL, name, 0);
}

mfso::~mfso()
{
}

// bool		mfso::registerDecoder(std::string name, Decoder&)
// {
// }

// bool		mfso::unregisterDecoder(std::string name)
// {
// }

// Node		*createNode(Node *parent, Decoder *decoder, uint64_t offset)
// {
// }

int32_t 	mfso::vopen(Node *node)
{
  std::cout << "mfso vopen" << std::endl;
  return 0;
}

int32_t 	mfso::vread(int fd, void *buff, unsigned int size)
{
}

int32_t 	mfso::vwrite(int fd, void *buff, unsigned int size)
{
}

int32_t 	mfso::vclose(int fd)
{
}

uint64_t	mfso::vseek(int fd, dff_ui64 offset, int whence)
{
}

uint32_t	mfso::status(void)
{
  return 0;
}
