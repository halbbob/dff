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

#ifndef __PFF_HH__
#define __PFF_HH__

#include "pff_common.hpp"
#include "pff_node.hpp"
#include "pff_macro.hpp"

using namespace std;

class pff : public mfso
{
private:
  Node*			parent;
  FdManager*		__fdm;
  libpff_file_t*	pff_file;
  libpff_error_t*	pff_error;
  int			export_attachments(Node*, libpff_item_t*);
public:
                         pff();
                        ~pff();
  void		        initialize(std::string path);
  void		        info();
  void		        info_file();
  void		        info_message_store();
  void		        info_unallocated_blocks();
  void		        create_item();
  void		        export_sub_items(libpff_item_t* item, Node* parent);
  int 		        export_item(libpff_item_t* item, int item_index, int number_of_items, Node* parent);
  int 		        export_email(libpff_item_t* item, int item_index,  Node* parent);
  int			export_attachments(libpff_item_t* item, Node* parent);
  int 		        export_folder(libpff_item_t* folder, int folder_index, Node* parent);
  int		        export_sub_folders(libpff_item_t* folder, PffNodeFolder* nodeFolder);
  int		        export_sub_messages(libpff_item_t* folder, PffNodeFolder* message);
  int32_t       	vopen(Node*);
  int32_t 	        vread(int fd, void *buff, unsigned int size);
  int32_t 	        vclose(int fd);
  int32_t       	vwrite(int fd, void *buff, unsigned int size) { return 0; };
  uint32_t      	status(void);
  uint64_t      	vseek(int fd, uint64_t offset, int whence);
  uint64_t      	vtell(int32_t fd);
  virtual void  	start(std::map<std::string, Variant*>);
};

#endif
