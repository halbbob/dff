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

#ifndef __DATA_STRUCTURE_H__
#define __DATA_STRUCTURE_H__

/*! \mainpage Extfs digital forensic driver.

    \section overview Overview.

    \subsection intro Intro

    Ext, or extended file system, created in 1992 by the French developer Remy
    Card, is the first file system specifically designed for Linux after
    limitations on the Minix file system were discovered.  It found his
    inspiration in the traditional UFS (Unix File System) and uses the same
    kind of meta-data, the inodes. It was simplified though and all the
    obsolete UFS structures kept only for compatibility were removed. It is the
    first extended file system.

    It was rapidly superseded by ext2fs and xiafs, between which was a
    competition loosed by  xiafs due to a low viability on short and mid term.

    Since this, two other versions of extfs are born :
        \li Ext3, which is a ext2 with a journal.
        \li Ext4, which uses extents.

    In 2008 the first stable version of Ext4 was released but still a lot of
    users have an operating system running with the Ext3 file system.

    We will in this document present the general functioning of ext, which is
    the same between the version 2, 3 and 4. Then we will present the specifics
    elements specific to ext3 and ext4. For ext3 it is mostly about the
    journal. For Ext4, we will talk about  the extents which improve the speed
    of the IO.

    \subsection brief Overview
	An ext file system is composed of blocks, themselves separated in block
	groups. Each block groups has the same number of blocks, instead the last
    one if the file system doesn't exactly match :
	\verbatim
        number of block per group * block size.
	\endverbatim

    Each block are the same size.


	An ext file system starts with a 1024 blocks which can contain a boot code,
	or 0s if there is no boot code. Data can be hidden in there.

	After this block, is a data structure called the super block. The super
	block is 1024 bytes big. The different fields of this structure can be
	seen as the file system configuration. It defines among other things the
	block size, the number of block per groups, the number of non allocated
	blocks, etc. In the block following the one where the super block is
	located is a group descriptor table. This structure can be found in every
	group. It describes, for a group, the position of block bitmap table, the
	inode bitmap table and the inode table. There is one group descriptor per
	group. The block bitmap and inode bitmap respectively contains the
	allocation status of blocks and inode.

	The inode table follows these blocks. Inode are very important on an ext
	file system. They are meta data structures used for each files. And
	remember that everything is a file, so everything on the file system is
	associated with an inode (regular files, directories, symlink, peripherals,
	socket, …).

	In the inode are block pointers which are used to “point” on files content.
	There are 12 direct blocks content, stored directly in the inode, one
	single indirect block pointer, one double indirect block pointer and one
	triple indirect block pointer.

	Usually the root directory is associated with inode 2. Notice that the type
	of file is defined in the file mode field of the inode. This is only real
	difference between the inode of a regular file and a directory inode.

	The content is different too. As we already said it is pointed by block
	pointers. If the file is a regular file, the block pointers will point the
	file content. If it a directory block pointers will point a set of data
	structure called directory entries which represent the files in the
	directory. Directory entries are composed of a file name and an inode
	number. In other words, file names are not stored in Inodes which means in
	some cases file names can be retrieved from a deletion but not the
	associated data. There are 2 other field in a directory entry :

        \li the entry length
        \li the file name length.

	The entry length is aligned on 4 bytes and is at least
	\verbatim
		directory entry structure size + file name length.
    \endverbatim

	If the directory entry is the last of the block, the directory entry length
	will point to the end of the block. Otherwise it points to the next
	directory entry. When a file is deleted, his directory entry is “hidden”,
	not physically removed from the disk. This is done by extending the size of
	the previous directory entry to the one following the deleted plop pouet
	caca ################ a reecrirer #######.

	Each directory contains at least two directory entries for “.” and “..”
	which are hard links respectively pointing to the current and the parent
	directory.

    \subsection todo Generic todo list
    For technical todos, see the todo page of doxygen.

    \todo
    \li Orphans management (list lost+found content + go to the inode).
    \li journal commands
    \li anti forensic counter measure.
    \li User codumentation.

    \bug
        \li Infinite loop sometimes if an inode was allocated the de-allocated
        then reallocated (in the journal the re-allocation is found, not the
        first allocation).

    \section user_man User manual.
    \subsection opt_SB_check --SB_check

    This option purpose is to look for superblock backup, even if the "original"
    is valid. This is done by carving the superblock signature, 0xEF53.

    This option can take 2 values :
        \li yes
        \li no

    If SB_check is set to \e \b yes, the driver will always look for backup when it is
    launched. Otherwise, it will search for superblock backup only when the main
    superblock is considered as invalid.

    The results are printed under the form:
    \verbatim
    Hit : offset    Previous : offset_previous (offset - offset_previous) -> Validity
    \endverbatim

    Exemple:
    \code
     $> dff.py
        [REMOVED]
     Forcing superblock check : trying to locate a backup.
     Hit : 2 Previous : 0 (2)         -> Possibly valid.
     Hit : 262144    Previous : 2 (262142)    -> Possibly valid.
     Hit : 786432    Previous : 262144 (524288)       -> Possibly valid.
     Hit : 1310720   Previous : 786432 (524288)       -> Invalid.
     Hit : 1835008   Previous : 1310720 (524288)      -> Possibly valid.
    \endcode

    \subsection opt_run --run

    If this option is set to \b \e no, the driver will not browse the file
    system. It is usefull when the user want to execute an other option
    where the file system parsing is not required.

    \subsection opt_fsstat --fsstat

    If this option is set to \b \e yes, the driver will display informations
    about the file system and the different group.

    \subsection opt_istat --istat

    If this option is set to \b \e yes, the driver will display informations
    about an or several inodes.

    Examples of use:

    For 1 inode:
    \verbatim
    --extfs /my_dump.dd --istat 42
    \endverbatim

    For several inodes:
    \verbatim
    --extfs /my_dump.dd --istat 42,43,44
    \endverbatim

    \subsection sb_addr --SB_addr
    Force the superblock address of the superblock.

    \subsection jstat --jstat
    Dsiplay some informations about the journal. Only available on ext3.
    \verbatim
    Journal stat :
	Journal inode : 8
        Super block version : 2
        Block size : 1024
        Number of blocks : 1024
        Block first transaction : 0
    0 : Unknown block. 
    1 : Descriptor block (Seq 28)
    2: Fs block     5
    3: Fs block     6
    2 : Unknown block. 
    3 : Unknown block. 
    4 : Commit block (Seq 28)
    5 : Unknown block. 
    6 : Commit block (Seq 17)
    7 : Descriptor block (Seq 18)
    8: Fs block     6
    8 : Unknown block. 
    [REMOVED]
    \endverbatim

*/

#include "includes/DirEntry.h"
#include "includes/SuperBlock.h"
#include "includes/GroupDescriptor.h"
#include "includes/Inode.h"
#include "includes/BootCode.h"

#endif
