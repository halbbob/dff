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

PffNodeUnallocatedPageBlocks::PffNodeUnallocatedPageBlocks(std::string name, Node *parent, fso* fsobj, libpff_error_t** error, libpff_file_t** file) : Node(name, 0, parent, fsobj)
{
  //this->setFile();
  this->pff_file = file;
  this->pff_error = error;

//XXX set Size 
}

void	PffNodeUnallocatedPageBlocks::fileMapping(FileMapping* fm)
{

  off64_t offset                   = 0;
  size64_t size                    = 0;
  int number_of_unallocated_blocks = 0;
  int block_iterator               = 0;

  if (libpff_file_get_number_of_unallocated_blocks(*(this->pff_file), LIBPFF_UNALLOCATED_BLOCK_TYPE_PAGE, &number_of_unallocated_blocks, this->pff_error) != 1)
    throw vfsError(std::string("unable to retrieve number of unallocated page blocks."));
  cout << "Found " << number_of_unallocated_blocks << " unallocated page blocks" << endl;

  if (number_of_unallocated_blocks > 0)
  {
     for (block_iterator = 0; block_iterator < number_of_unallocated_blocks; block_iterator++)
     {
	if (libpff_file_get_unallocated_block(*(this->pff_file), LIBPFF_UNALLOCATED_BLOCK_TYPE_PAGE, block_iterator, &offset, &size, this->pff_error) == 1)
	  printf("%016llx - %016llx size : %lld\n", offset, offset + size, size);	
     }
  }
//  fm->push(voffset, size, parent, offset);
}
