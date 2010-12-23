/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
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

#ifndef __WINDEVICES_HH__
#define __WINDEVICES_HH__

#include "mfso.hpp"
#include <string>
#include <iostream>
#include <stdio.h>
#include <list>
#include <vector>
#include "type.hpp"
#include "vfs.hpp"
#include "conf.hpp"

#pragma comment(lib, "advapi32.lib")

#include <windows.h>
#include <stdio.h>
#include <aclapi.h>

using namespace std;

class DeviceNode : public Node
{
	
public:
	std::string		__devname;	
	DeviceNode(std::string devname, uint64_t size, fso* fsobj,std::string name);
	
};

class DeviceBuffer
{
private:
  uint8_t*			__buffer;
  uint64_t			__offset;
  uint32_t			__BPS;
  DWORD				__currentSize;
  HANDLE			__handle;
  uint64_t			__devSize;
  void				fillBuff(uint64_t offset);
public:
  DeviceBuffer(HANDLE handle, uint32_t size, uint32_t BPS,  uint64_t DevSize);
  ~DeviceBuffer();
   uint32_t			__size;
  int32_t			getData(void* buff, uint32_t size, uint64_t offset);
};

class windevices : public fso
{
private:
  Node				*parent;
  class Node*		__root;
  FdManager*		__fdm;
public:
  std::string devicePath;
  windevices();
  ~windevices();
  int32_t	vopen(Node* handle);
  int32_t 	vread(int fd, void *buff, unsigned int size);
  int32_t 	vclose(int fd);
  uint64_t 	vseek(int fd, uint64_t offset, int whence);
  int32_t	vwrite(int fd, void *buff, unsigned int size) { return 0; };
  uint32_t	status(void);
  uint64_t	vtell(int32_t fd);
  virtual void	start(argument* ar);
};
#endif
