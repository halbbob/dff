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

#include "data_structure/extfs_struct/types.h"
#include "data_structure/includes/SuperBlock.h"
#include "include/RegularFile.h"
#include "vfs.hpp"

#ifndef __EXTFSFILE_H__
#define __EXTFSFILE_H__

class Extfs;
class ExtfsFile
{
    public:
                    ExtfsFile(dff_ui64, int);
                    ~ExtfsFile();

        dff_ui64    getOffset();
        dff_ui64    getVfileOffset();
        uint32      getCurrentBlock();
        uint32      getBlockOnVfs();
        void        setVFileOffset(dff_ui64 addr) { _vfile_offset = addr; }
        void        setBlockOnVfs(uint32 block)     { _block_on_vfs = block; }
        void        setBlock(uint32 block) { _current_block = block; }
        int         getFd();
        uint32      getInodeAddr();
        dff_ui64    seekSet(dff_ui64, RegularFile *, SuperBlock *);
        dff_ui64    seekCur(dff_ui64, RegularFile *, SuperBlock *);

    private:
        dff_ui64    _offset;
        uint32      _vfile_offset;
        uint32      _inode_addr;
        uint32      _current_block;
        uint32      _block_on_vfs;
        int         _fd;
};

#endif // __EXTFSFILE_H__
