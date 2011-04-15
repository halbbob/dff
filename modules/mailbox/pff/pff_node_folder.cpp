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


PffNodeFolder::PffNodeFolder(std::string name, Node* parent, fso* nfsobj) : Node(name, 0, parent, nfsobj)
{
  this->setDir();
}

PffNodeFolder::~PffNodeFolder()
{
}

std::string	PffNodeFolder::icon()
{
 //inbox
 //deleted
 //outbox 
 //sent items
//contacts
//XXX 
  if (this->name().find("Sent") != std::string::npos)
    return (":folder_sent_mail");
  if (this->name().find("Outbox") != std::string::npos)
    return (":folder_outbox");
  if (this->name().find("Deleted") != std::string::npos)
    return (":mail_delete");
  if (this->name().find("Inbox") != std::string::npos) //en francais ? regarder ds les attribut plutot ...
    return (":folder_inbox");
  return (":folder_128.png");
}
