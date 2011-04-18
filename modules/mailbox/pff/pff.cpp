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


pff::pff() : mfso("pff")
{
  
}

pff::~pff()
{
}

void pff::start(std::map<std::string, Variant*> args)
{
  string 	path;
  
  if (args["file"] != NULL)
    this->parent = args["file"]->value<Node* >();
  else
    throw envError("pff need a file argument.");
  try 
  {
    this->initialize(this->parent->absolute());
//    this->info(); // optional return as variant results ? 
    this->create_unallocated();
    this->create_item();
  }
  catch (vfsError e)
  {
     res["error"] = new Variant(e.error);
     return ;
  }
  
 //XXX
// this->registerTree(parent, son); 
//    libpff_file_close(this->pff_file, *(this->error));
  //  libpff_file_free(this->pff_file, *(this->error));

/*
  if (libpff_file_info_fprint(stdout, pff_file) != 1)
  {
     res->add_const("error", "Can't print file info.");
     return; 
  }
*/

  res["result"] = new Variant(std::string("Mailbox parsed successfully."));
}

void	pff::create_unallocated(void)
{
   PffNodeUnallocatedBlocks*  unallocatedPage = new PffNodeUnallocatedBlocks(std::string("unallocated page blocks"), NULL, this, this->parent, LIBPFF_UNALLOCATED_BLOCK_TYPE_PAGE, &(this->pff_error), &(this->pff_file));
   this->registerTree(this->parent, unallocatedPage);

   PffNodeUnallocatedBlocks*  unallocatedData = new PffNodeUnallocatedBlocks(std::string("unallocated data blocks"), NULL, this, this->parent, LIBPFF_UNALLOCATED_BLOCK_TYPE_DATA, &(this->pff_error), &(this->pff_file));
   this->registerTree(this->parent, unallocatedData);
}


void pff::create_item()
{
  if (libpff_file_recover_items(this->pff_file, 0, &(this->pff_error)) != 1)
    throw vfsError(std::string("Unable to recover items."));
	
   libpff_item_t *pff_root_item = NULL;
   int number_of_sub_items      = 0;

   if (libpff_file_get_root_folder(this->pff_file, &pff_root_item, &(this->pff_error)) != 1)
      throw vfsError(std::string("Unable to retrieve root item"));
   if (libpff_item_get_number_of_sub_items(pff_root_item, &number_of_sub_items, &(this->pff_error)) != 1)
      throw vfsError(std::string("Unable to retrive number of sub items."));
   if (number_of_sub_items > 0)
   {
     Node* mbox = new Node(std::string("mailbox"), 0, NULL, this);
     this->export_sub_items(pff_root_item, mbox);
//     if (libpff_item_free(&pff_root_item, &(this->pff_error)) != 1)
  //     throw vfsError(std::string("Unable to free root item."));
     this->registerTree(this->parent, mbox);
   }  
}


void pff::initialize(string path)
{
  this->pff_file = NULL;
  this->pff_error = NULL;
  if (libpff_file_initialize(&(this->pff_file), &(this->pff_error)) != 1)
    throw vfsError(std::string("Unable to initialize system values."));
  if (libpff_file_open(this->pff_file, path.c_str(), LIBPFF_OPEN_READ , &(this->pff_error)) != 1)
    throw vfsError(std::string("error", "Can't open pff file."));
}


int32_t pff::vopen(Node* tnode)
{
  fdinfo*	fi;
  int32_t	fd;

  PffNodeData* node = dynamic_cast<PffNodeData *>(tnode);

  if (node == NULL)
  {
    PffNodeUnallocatedBlocks* pnode  = dynamic_cast<PffNodeUnallocatedBlocks *>(tnode); 
    if (pnode)
	 return (mfso::vopen(pnode));
    return (-1);
  }
  if (!node->size())
    return (-1);
 
  fi = node->vopen();
  if (fi == NULL)
    return (-1);
 
  fd = this->__fdmanager->push(fi);
  return (fd);
}

int32_t  pff::vread(int fd, void *buff, unsigned int size)
{
  fdinfo*				fi;
  try
   {
     fi = this->__fdmanager->get(fd);
   }
   catch (vfsError e)
   {
     return (0); 
   }
   PffNodeData* node = dynamic_cast<PffNodeData *>(fi->node);
   if (node == NULL)
   {
      if (dynamic_cast<PffNodeUnallocatedBlocks *>(fi->node))
	 return (mfso::vread(fd, buff, size));
      return (0);
   }
   return (node->vread(fi, buff, size));
}

int32_t pff::vclose(int fd)
{
  fdinfo*		fi;
  PffNodeData*		node;

  try
  {
    fi = this->__fdmanager->get(fd);
    node = dynamic_cast<PffNodeData* >(fi->node);
    PffNodeData* node = dynamic_cast<PffNodeData *>(fi->node);
    if (node == NULL)
    {
      if(dynamic_cast<PffNodeUnallocatedBlocks *>(fi->node))
	 return (mfso::vclose(fd));
      return (-1);
    }
    node->vclose(fi);
    this->__fdmanager->remove(fd);
  }
  catch (vfsError e)
  {
    return (-1); 
  }

  return (0);
}

uint64_t pff::vseek(int fd, uint64_t offset, int whence)
{
  fdinfo*		fi;
  PffNodeData*		node; 

  try
  {
    fi = this->__fdmanager->get(fd);
    node = dynamic_cast<PffNodeData*>(fi->node);
    if (node == NULL)
    {
      if (dynamic_cast<PffNodeUnallocatedBlocks *>(fi->node)) 
	 return (mfso::vseek(fd, offset, whence));
      return ((uint64_t) -1);
    }
    return (node->vseek(fi, offset, whence));
  }
  catch (vfsError e)
  {
    return ((uint64_t) -1);
  }
  
  return ((uint64_t) -1);
}

uint64_t	pff::vtell(int32_t fd)
{
  fdinfo*	fi;

  try
  {
      fi = this->__fdmanager->get(fd);
      return (fi->offset);
  }
  catch (vfsError e)
  {
      return (uint64_t)-1; 
  }
}

uint32_t pff::status(void)
{
  return (0);
}
