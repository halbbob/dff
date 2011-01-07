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

#include "wdevices.hpp"
#include <String>
#include <windows.h>
#include <shlwapi.h>

DeviceNode::DeviceNode(std::string devname, uint64_t size, fso* fsobj,std::string name = "") : Node(devname, size, 0, fsobj)
{
  if (name != "")
    this->__name = name;
  else
    this->__name = devname;
  this->__devname = devname;
}

DeviceBuffer::DeviceBuffer(HANDLE hndl, uint32_t size,  uint32_t bps, uint64_t devSize)
{
	this->__handle = hndl;
	this->__size = size * bps;
	this->__currentSize = 0;
	this->__BPS	= bps;
	this->__buffer = (uint8_t *)malloc(this->__size);
	this->__offset = 0;
	this->__devSize = devSize;
	this->fillBuff(0);
}

DeviceBuffer::~DeviceBuffer()
{
   CloseHandle(this->__handle);
   free(this->__buffer);
}

void DeviceBuffer::fillBuff(uint64_t offset)
{
	LARGE_INTEGER sizeConv;
	LARGE_INTEGER newOffset;
	
	if (this->__offset > this->__devSize)
	{
		this->__currentSize = 0;
		return;
	}
	this->__offset = ((offset / this->__BPS) * this->__BPS);
	sizeConv.QuadPart = this->__offset;
	SetFilePointerEx(this->__handle, sizeConv, &newOffset, 0);
	DWORD gsize;
	if (this->__offset + this->__size > this->__devSize)
		gsize = this->__devSize - this->__offset;
	else
		gsize = this->__size;
	ReadFile(this->__handle, (void*)(this->__buffer), gsize,  &(this->__currentSize) ,0);
}

int32_t	DeviceBuffer::getData(void *buff, uint32_t size, uint64_t offset)
{
	if ((offset < this->__offset) || (offset > this->__offset + this->__currentSize) 
		||(offset + size > this->__offset + this->__currentSize))
	{
	  this->fillBuff(offset);
	}

	uint64_t leak = offset - this->__offset;
	if (size > this->__currentSize - leak)
		size = this->__currentSize - leak;
	memcpy(buff, ((char*)this->__buffer + leak), size);

	return ((int32_t)size);
}


windevices::windevices(): fso("windevices")
{
	this->__fdm = new FdManager;
}

windevices::~windevices()
{
}

void						windevices::start(argument *arg)
{
  std::string		path;
  Path				*lpath;
  s_ull				sizeConverter;
  uint64_t			size =0;
  std::string		nname;

  try
  {	 
    arg->get("parent", &(this->parent));
  }
  catch (envError e)
  {
    this->parent = VFS::Get().GetNode("/");
  }
  try 
  {
    arg->get("path", &lpath);
  } 
  catch (envError e)
  {
     res->add_const("error", "conf " + e.error);
     return ;
  }
  try
  {
    arg->get("size", &size);
  }
  catch (envError e)
  {
     size = 0;
  }
  try 
  {
    arg->get("name", &nname);
  }
  catch (envError e)
  {
    nname = "";
  }
  this->devicePath = lpath->path;
  sizeConverter.ull = size;
 
  HANDLE hnd = CreateFileA(this->devicePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
			     0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if (((HANDLE)hnd) == INVALID_HANDLE_VALUE)
  {
	res->add_const("error", string("can't open devices"));
    return ;
  }
  else
  {
    LPDWORD lpBytesReturned = 0;
	DeviceIoControl(hnd, FSCTL_ALLOW_EXTENDED_DASD_IO, NULL, 0, NULL, 0, lpBytesReturned, NULL);
    if (!size)
	{
	  GET_LENGTH_INFORMATION diskSize;
	  if (DeviceIoControl(hnd, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &diskSize, sizeof(diskSize), lpBytesReturned,0))
	     size = (uint64_t)diskSize.Length.QuadPart;
	  CloseHandle(hnd);
	}
    this->__root = new DeviceNode(this->devicePath, sizeConverter.ull,  this, nname);
	this->__root->setFile();
    this->registerTree(this->parent, this->__root);
  }	
}


int windevices::vopen(Node *node)
{
  fdinfo*	fi;
  int32_t	fd;

  if (node != NULL) 
  {
    fi = new fdinfo;
	int hnd = (int)CreateFileA(((DeviceNode*)node)->__devname.c_str(), GENERIC_READ, FILE_SHARE_READ,
			     0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	fi->fm = (FileMapping*)new DeviceBuffer((HANDLE)hnd, 100 * sizeof(uint8_t), 4096, node->size());
	fi->node = node;
	fi->offset = 0;
	fd = this->__fdm->push(fi);
	return (fd);
  }
  else
    return -1;
}

int windevices::vread(int fd, void *buff, unsigned int origSize)
{ 
	fdinfo*				fi;
	DeviceBuffer*		dbuff;
	uint32_t			readed;
	uint32_t			aReaded = 0;
	
    try
    {
      fi = this->__fdm->get(fd);
	  dbuff = (DeviceBuffer*)fi->fm;
    }
    catch (...)
    {
      return (0); 
    }

	while (aReaded < origSize)
	{
	  readed = dbuff->getData(((uint8_t *)buff + aReaded), origSize - aReaded, fi->offset);
	  fi->offset += ((uint64_t)readed);
	  aReaded += readed;
	  if (fi->offset > this->__root->size())
	  {
		fi->offset = this->__root->size();
		return (aReaded);
	  }
	  if (readed < dbuff->__size)
        return (aReaded); 
	}
	return aReaded;
}

int windevices::vclose(int fd)
{
 try
    {
      fdinfo* fi = this->__fdm->get(fd);
	  delete ((DeviceBuffer*)fi->fm);
	  this->__fdm->remove(fd);
      return (0);
    }
  catch (...)
    {
		return -1;
    }
}

uint64_t	windevices::vseek(int fd, uint64_t offset, int whence)
{
  fdinfo*	fi;
  Node*	node;

  try
    {
      fi = this->__fdm->get(fd);
      node = dynamic_cast<Node*>(fi->node);
	 
      if (whence == 0)
	  {
	    if (offset <= node->size())
		{
	      fi->offset = offset;
		  return (fi->offset);
		}
	  }
      else if (whence == 1)
	  {
  	    if (fi->offset + offset <= node->size())
		{
	      fi->offset += offset;
		  return (fi->offset);
		}
	  }
      else if (whence == 2)
	  {
	     fi->offset = node->size();
         return (fi->offset);
	  }
  }
  catch (...)
    {
	  return ((uint64_t) -1);
    }
   return ((uint64_t) -1);
  }

uint64_t	windevices::vtell(int32_t fd)
{
  fdinfo*	fi;

  try
    {
      fi = this->__fdm->get(fd);
      return (fi->offset);
    }
  catch (...)
    {
      return (uint64_t)-1; 
    }
}

unsigned int windevices::status(void)
{
  return (1);
}

