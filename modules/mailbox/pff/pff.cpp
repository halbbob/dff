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
  Path		*tpath;
   
  if (args["file"] != NULL)
    this->parent = args["file"]->value<Node* >();
  else
    throw envError("pff need a file argument.");
  try 
  {
    this->__fdm = new FdManager;
    this->initialize(this->parent->absolute());
    this->info();
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
 

 
  libpff_item_t*	root_folder = NULL;
  if (libpff_file_get_root_folder(pff_file, &root_folder, &error) != 1)
  {  
     res->add_const("error", "Can't get root folder.");
     return;
  }
*/

  res["result"] = new Variant(std::string("Mailbox parsed successfully."));
}
/*
int32_t pff:get_root_folder(libpff_file_t* file, libpff_item_t **root_folder, libpff_error_t** error)
{
  if ((libpff_file_get_root_folder(file, root_folder, error))
}
*/

void	pff::create_unallocated(void)
{
//XXX create with mailbox parent ?
   cout << "create unalocated pages block as a single node" << endl;
   new PffNodeUnallocatedPageBlocks(std::string("unallocated page blocks"), this->parent, this, &(this->pff_error), &(this->pff_file));

}


void pff::create_item()
{
//  export_handle_t *pffexport_export_handle = NULL;
//  libpff_file_t *pffexport_file            = NULL;

//cout << "Creating items" << endl;
  if (libpff_file_recover_items(this->pff_file, 0, &(this->pff_error)) != 1)
    throw vfsError(std::string("Unable to recover items."));
  //cout << "Exporting Items" << endl;
  ////mimic export_handle_export_items 
	//export handle make directory 
	
   libpff_item_t *pff_root_item = NULL;
   int number_of_sub_items      = 0;

   if (libpff_file_get_root_folder(this->pff_file, &pff_root_item, &(this->pff_error)) != 1)
      throw vfsError(std::string("Unable to retrieve root item"));
   if (libpff_item_get_number_of_sub_items(pff_root_item, &number_of_sub_items, &(this->pff_error)) != 1)
      throw vfsError(std::string("Unable to retrive number of sub items."));
   if (number_of_sub_items > 0)
   {
     //export_handle_export_sub_items
     Node* mbox = new Node(std::string("mailbox"), 0, NULL, this); //this facilitate the registering of the tree
//     this->export_sub_items(pff_root_item, this->parent);
     this->export_sub_items(pff_root_item, mbox);
//     if (libpff_item_free(&pff_root_item, &(this->pff_error)) != 1)
  //     throw vfsError(std::string("Unable to free root item."));
     this->registerTree(this->parent, mbox);
   }  

 
//  if (export_handle_initialize(&pffexport_export_handle) != -1)
  //  throw vfsError(std::string("Unable to create export handle."));

  //cout << "Items exported" << endl;
}


void pff::initialize(string path)
{
  this->pff_file = NULL;
  this->pff_error = NULL;
  if (libpff_file_initialize(&(this->pff_file), &(this->pff_error)) != 1)
    throw vfsError(std::string("Unable to initialize system values."));
  cout << "pff file open " << endl;
  if (libpff_file_open(this->pff_file, path.c_str(), LIBPFF_OPEN_READ , &(this->pff_error)) != 1)
    throw vfsError(std::string("error", "Can't open pff file."));
  cout << "pff file open ok" << endl;
}


int32_t pff::vopen(Node* tnode)
{
  fdinfo*	fi;
  int32_t	fd;
  uint8_t*	buff;
  

  PffNodeData* node = dynamic_cast<PffNodeData *>(tnode);

  if (node == NULL)
    return (-1);
  if (!node->size())
    return (-1);
 
  fi = node->vopen();
  if (fi == NULL)
    return (-1);
 
  fd = this->__fdm->push(fi);
  return (fd);
}

int32_t  pff::vread(int fd, void *buff, unsigned int size)
{
  fdinfo*				fi;
  try
   {
     fi = this->__fdm->get(fd);
   }
   catch (...)
   {
     return (0); 
   }
   PffNodeData* node = dynamic_cast<PffNodeData *>(fi->node);
   return (node->vread(fi, buff, size));
}

int32_t pff::vclose(int fd)
{
  fdinfo*		fi;
  uint8_t*		rbuff;
  PffNodeData*		node;

  try
  {
    fi = this->__fdm->get(fd);
    node = dynamic_cast<PffNodeData* >(fi->node);
    node->vclose(fi);
    this->__fdm->remove(fd);
  }
  catch (...)
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
    fi = this->__fdm->get(fd);
    node = dynamic_cast<PffNodeData*>(fi->node);

    return (node->vseek(fi, offset, whence));

    }
  catch (...)
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
      fi = this->__fdm->get(fd);
      return (fi->offset);
    }
  catch (...)
    {
      return (uint64_t)-1; 
    }
}

uint32_t pff::status(void)
{
  return (0);
}
