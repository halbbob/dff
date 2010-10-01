/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 *
 * Author(s):
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

#ifndef REGULARFILE_H
#define REGULARFILE_H

#include "../data_structure/includes/Inode.h"


class RegularFile : public Inode
{
public:
    RegularFile(Extfs *, SuperBlock *);
    ~RegularFile();

    virtual void        directBlockContent();
    virtual void        singleIndirectBlockContent();
    virtual void        doubleIndirectBlockContent();
    virtual void        tripleIndirectBlockContent();

    dff_ui64            goToBlock(uint32);

protected:
private:
};

#endif // REGULARFILE_H
