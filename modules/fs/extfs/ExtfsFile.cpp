/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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

#include "include/ExtfsFile.h"

ExtfsFile::ExtfsFile(dff_ui64 inode_addr, int fd)
{
    _offset = 0;
    _fd = fd;
    _inode_addr = inode_addr;
    _current_block = 0;
    _vfile_offset = 0;
    _block_on_vfs = 0;
}

ExtfsFile::~ExtfsFile()
{
}

dff_ui64    ExtfsFile::seekCur(dff_ui64 offset, RegularFile * file,
                               SuperBlock * SB)
{
    if ((offset + this->_offset) >= file->getSize())
    {
        return -1;
    }
    this->_offset += offset;
    return this->_offset;
}

dff_ui64    ExtfsFile::seekSet(dff_ui64 offset, RegularFile * file,
                               SuperBlock * SB)
{
    if (offset >= file->getSize())
    {
        return -1;
    }
    return offset;
}

uint32      ExtfsFile::getInodeAddr()
{
    return _inode_addr;
}

dff_ui64    ExtfsFile::getOffset()
{
    return _offset;
}

int         ExtfsFile::getFd()
{
    return _fd;
}

dff_ui64    ExtfsFile::getVfileOffset()
{
    return _vfile_offset;
}

uint32      ExtfsFile::getCurrentBlock()
{
        return this->_current_block;
}

uint32      ExtfsFile::getBlockOnVfs()
{
        return this->_block_on_vfs;
}
