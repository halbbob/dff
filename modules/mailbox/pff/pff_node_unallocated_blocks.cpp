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


/*concatenate all unallocated page blocks*/
PffNodeUnallocatedPageBlocks::PffNodeUnallocatedPageBlocks(std::string name, Node *parent, mfso* fsobj, Node* root, libpff_error_t** error, libpff_file_t** file) : Node(name, 0, parent, fsobj)
{
  //this->setFile();
  off64_t offset                   = 0;
  size64_t size                    = 0;
  int number_of_unallocated_blocks = 0;
  int block_iterator               = 0;
  uint64_t  node_size		   = 0;

  this->pff_file = file;
  this->pff_error = error;

  if (libpff_file_get_number_of_unallocated_blocks(*(this->pff_file), LIBPFF_UNALLOCATED_BLOCK_TYPE_PAGE, &number_of_unallocated_blocks, this->pff_error) != 1)
    throw vfsError(std::string("unable to retrieve number of unallocated page blocks."));
  cout << "Found " << number_of_unallocated_blocks << " unallocated page blocks" << endl;

  if (number_of_unallocated_blocks > 0)
  {
     for (block_iterator = 0; block_iterator < number_of_unallocated_blocks; block_iterator++)
     {
	if (libpff_file_get_unallocated_block(*(this->pff_file), LIBPFF_UNALLOCATED_BLOCK_TYPE_PAGE, block_iterator, &offset, &size, this->pff_error) == 1)
	{
	  node_size += size;	
	}
     }
  } 
  this->setSize(node_size);
}

void	PffNodeUnallocatedPageBlocks::fileMapping(FileMapping* fm)
{

  off64_t offset                   = 0;
  size64_t size                    = 0;
  int number_of_unallocated_blocks = 0;
  int block_iterator               = 0;
  uint64_t voffset		   = 0;

  cout << "file mapping " << endl;
  if (libpff_file_get_number_of_unallocated_blocks(*(this->pff_file), LIBPFF_UNALLOCATED_BLOCK_TYPE_PAGE, &number_of_unallocated_blocks, this->pff_error) != 1)
    throw vfsError(std::string("unable to retrieve number of unallocated page blocks."));

  if (number_of_unallocated_blocks > 0)
  {
     for (block_iterator = 0; block_iterator < number_of_unallocated_blocks; block_iterator++)
     {
	if (libpff_file_get_unallocated_block(*(this->pff_file), LIBPFF_UNALLOCATED_BLOCK_TYPE_PAGE, block_iterator, &offset, &size, this->pff_error) == 1)
	{
	  fm->push(voffset, size, this->root, offset);
	  voffset += size;	
	}
     }
  }
}
