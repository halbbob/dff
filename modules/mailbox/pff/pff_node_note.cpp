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

PffNodeNote::PffNodeNote(std::string name, Node* parent, fso* fsobj, libpff_item_t* task, libpff_error_t** error, libpff_file_t** file, bool clone) : PffNodeEmailMessageText(name, parent, fsobj, task, error, file, clone)
{
}
