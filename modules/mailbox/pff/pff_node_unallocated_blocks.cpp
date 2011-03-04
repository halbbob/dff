PffNodeUnallocatedPageBlocks::PffNodeUnallocatedPageBlocks(std::string name, Node *parent, fso* fsobj) : Node(name, 0, parent, fsobj)
{
  //this->setFile();
}

void	PffNodeUnallocatedPageBlocks::fileMapping(FileMapping* fm)
{
/*
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

*/
   fm->push(voffset, size, parent, offset);
}
