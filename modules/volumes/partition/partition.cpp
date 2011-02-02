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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include "partition.hpp"

// bool	Partition::isExtended(char type)
// {
//    char	ext[] = "\x05\x0F\x85\x91\x9B\xD5";
//    unsigned int	i;
//    bool	res;
  
//    res = false;
//    for (i = 0; ext[i]; i++)
//      if (ext[i] == type)
//        res = true;
//    return res;
// }

// Node	*Partition::createPart(Node *parent, unsigned int sector_start, unsigned int size)
// {
//   attrib		*attr;
//   FileInfo		*fi;
//   unsigned long long	handle;

//   std::ostringstream os;

//   attr = new attrib;
//   fi = new FileInfo();
//   fi->start = sector_start * 512;
//   fi->size = size * 512;
//   handle = this->filehandler->add(fi);
//   attr->size = fi->size;
//   attr->handle = new Handle(handle);
//   os << "Partition " << this->part_count;
//   this->part_count += 1;
//   return CreateNodeFile(parent, os.str(), attr);
// }

// string	Partition::hexilify(char type)
// {
//   std::ostringstream		res;
  
//   res << std::hex << std::setiosflags(ios_base::showbase | ios_base::uppercase);
//   res << (int)type;
//   return res.str();
// }

// void	Partition::readExtended(Node *parent, unsigned int start, unsigned int next_lba)
// {
//   ebr			ebrEntry;
//   unsigned long long	startOffset;
//   unsigned long long	endOffset;
//   unsigned int	        i;
//   bool			jumped;
//   partition_entry	*part;
 
//   startOffset = start + next_lba;
//   this->Seek(startOffset * 512);
//   memset(&ebrEntry, 0, sizeof(ebr));
//   if (this->Read(&ebrEntry, sizeof(ebr)) != 0)
//     {
//       jumped = false;
//       part = (partition_entry*)malloc(sizeof(partition_entry));
//       for (i = 0; i != 4; i++)
//   	{
//   	  if (ebrEntry.part[i].type != 0)
//   	    {
//   	      memcpy(part, &(ebrEntry.part[i]), sizeof(partition_entry));
//   	      if (((i < 2) && jumped) || (i >= 2))
//   		this->Result << "Hidden partition !!!" << endl;
//   	      if (isExtended(part->type))
//   		this->readExtended(parent, start, part->lba);
//   	      else
//   		{
//   		  this->Result << "   +- Partition " << this->part_count << endl;
//   		  this->Result << "      |-- type  : " << this->hexilify(part->type) << endl;
//   		  this->Result << "      |-- start : " << part->lba + startOffset << endl;
//   		  this->Result << "      |-- end   : " << part->lba - 1 + part->total_blocks << endl;
//   		  this->Result << "      |-- size  : " << part->total_blocks << endl;
//   		  this->createPart(parent, part->lba + startOffset, part->total_blocks);
//   		}
//   	    }
//   	  else if (i < 2)
//   	    jumped = true;
//   	}
//     }
// }


//Only checking the type is not enough !!!
//anybody could set type to 0 to fake partition manager...
// void	Partition::readMbr()
// {
//   unsigned int		i;
//   partition_entry	*part;
//   bool			jumped;
//   Node			*node;

//   memset(&mbrEntry, 0, sizeof(mbr));
//   if (this->Read(&mbrEntry, sizeof(mbr)) != 0)
//     {
//       jumped = false;
//       part = (partition_entry*)malloc(sizeof(partition_entry));
//       for (i = 0; i != 4; i++)
//   	{
//   	  if (mbrEntry.part[i].type != 0)
//   	    {
//   	      if (jumped)
//   		this->Result << "Hidden primary partition entry" << endl;
//   	      memcpy(part, &(mbrEntry.part[i]), sizeof(partition_entry));
//   	      if (this->isExtended(part->type))
//   		{
//   		  this->Result << "+- Partition " << this->part_count << " (extended)" << endl;
//   		  this->Result << "    |-- type  : " << this->hexilify(part->type) << endl;
//   		  this->Result << "    |-- start : " << part->lba << endl;
//   		  this->Result << "    |-- end   : " << part->lba - 1 + part->total_blocks << endl;
//   		  this->Result << "    |-- size  : " << part->total_blocks << endl;
//   		  node = this->createPart(this->ParentNode, part->lba, part->total_blocks);
//   		  this->readExtended(node, part->lba, 0);
//   		}
//   	      else
//   		{
//   		  this->Result << "+- Partition " << this->part_count << " (primary)" << endl;
//   		  this->Result << "    |-- type  : " << this->hexilify(part->type) << endl;
//   		  this->Result << "    |-- start : " << part->lba << endl;
//   		  this->Result << "    |-- end   : " << part->lba - 1 + part->total_blocks << endl;
//   		  this->Result << "    |-- size  : " << part->total_blocks << endl;
//   		  this->createPart(this->ParentNode, part->lba, part->total_blocks);
//   		}
//   	    }
//   	  else
//   	    jumped = true;
//   	}
//       free(part);
//     }
// }


void Partition::start(argument* arg)
{
  try
    {
      arg->get("files", &this->parent);
      if (this->parent->size() != 0)
	{
	  this->__root = new Node("partition");
	  this->__root->setDir();
	  this->__root->setFsobj(this);
	  this->dos->open(this->parent->open(), 0, this->__root, this, this->parent);
	  this->registerTree(this->parent, this->__root);
	}
    }
  catch(envError e)
    {
      delete this->__root;
      throw envError("[PARTITION] parent argument not provided\n" + e.error);
    }
  catch(vfsError e)
    {
      delete this->__root;
      throw vfsError("[PARTITION] error while processing file\n" + e.error);
    }
}

// int	Partition::SetResult()
// {
//   return (0);
// }

Partition::Partition(): mfso("partition")
{
  this->dos = new DosPartition();
}

Partition::~Partition()
{
  //Free All Memory !!!
  cout << "Dump Closed successfully" << endl;
}
