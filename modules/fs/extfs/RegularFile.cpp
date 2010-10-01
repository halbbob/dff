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

#include "include/RegularFile.h"

RegularFile::RegularFile(Extfs * ext, SuperBlock * SB) : Inode(ext, SB)
{
    //ctor
}

RegularFile::~RegularFile()
{
    //dtor
}

void    RegularFile::directBlockContent()
{

}

void    RegularFile::singleIndirectBlockContent()
{

}

void    RegularFile::doubleIndirectBlockContent()
{

}

void    RegularFile::tripleIndirectBlockContent()
{

}

dff_ui64    RegularFile::goToBlock(uint32 block_number)
{
    dff_ui64    addr = 0;

    std::cout << "block addr: " << addr << std::endl;
    if (block_number < 12)
    {
        addr = this->block_pointers()[block_number];
        _vfile->seek(addr * this->_SB->block_size());

        std::cout << "block addr: " << addr << std::endl;
        return addr;
    }
    else if ((block_number - 12) < (this->_SB->block_size() / 4))
    {
        addr = this->simple_indirect_block_pointer() * this->_SB->block_size();
        addr += (block_number - 12) * this->_SB->block_size();
        _vfile->seek(addr);
        std::cout << "double block addr : " << addr << std::endl;
        return addr;
    }
 /*   else if (0)
    {
    }
    else if (0)
    {
    } */
    return -1;
}
