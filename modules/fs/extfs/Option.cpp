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
 * DFF for assistance; the proje`ct provides a web site, mailing lists
 * and IRC channels for your use.
 *
 * Author(s):
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

#include <memory>

#include "include/Option.h"
#include "include/FsStat.h"
#include "include/InodeStat.h"
#include "include/InodesList.h"
#include "include/JournalStat.h"
#include "include/BlkList.h"
#include "include/DirLs.h"

Option::Option(argument * arg, SuperBlock * SB, VFile * vfile,
	       GroupDescriptor * GD)
{
  __arguments = arg;
  __SB = SB;
  __vfile = vfile;
  __GD = GD;
}

Option::~Option()
{
}

void	Option::parse(Extfs * extfs)
{
  std::string	blk(""), dir_path(""), istat_opt("");
  std::string	ils(""), jstat("");
  bool		fs_stat = false;

  extfs->arg_get(__arguments, "jstat", &jstat);
  extfs->arg_get(__arguments, "blk", &blk);
  //  extfs->arg_get(__arguments, "dir_ls", &dir_path);
  extfs->arg_get(__arguments, "fsstat", &fs_stat);
  fs_stat = !fs_stat;
  extfs->arg_get(__arguments, "ils", &ils);
  extfs->arg_get(__arguments, "istat", &istat_opt);

  // stat on file system
  if (fs_stat)
    {
      std::auto_ptr<FsStat>   stat(new FsStat);
      stat->disp(__SB, __vfile);
    }

  // inodes list
  if (!ils.empty())
    {
      std::auto_ptr<InodesList>   i_list(new InodesList(__SB, __vfile));
      i_list->list(ils, __SB->inodesNumber());
      i_list->display(extfs);
    }

  // stat on an inode
  if (!istat_opt.empty())
    {
      std::auto_ptr<InodeStat>   i_stat(new InodeStat(__SB, extfs));
      i_stat->stat(istat_opt);
    }

  // stat on the journal (if there is any)
  if (!jstat.empty())
    {
      std::auto_ptr<JournalStat> j_stat(new JournalStat(extfs, __SB, __GD));
      j_stat->stat();
    }

  // block list
  if (!blk.empty())
    {
      std::auto_ptr<BlkList>	blk_list(new BlkList(__GD, __SB, __vfile));
      blk_list->stat(blk);
    } 
}
