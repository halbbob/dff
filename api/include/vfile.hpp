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
 *  Solal J. <sja@digital-forensic.org>
 */

#ifndef __VPATH_HH__
#define __VPATH_HH__

#include <stdlib.h> 
#include <string>
#include <string.h>
#include "node.hpp"
#include "type.hpp"
#include "export.hpp"
#include "search.hpp"
#include "mfso.hpp"
#include <stdint.h>

using namespace std;

#define BUFFSIZE 1024*1024*10

typedef struct _pdata
{
  void *buff;
  dff_ui64 len;
} pdata;


class VFile
{
private:
  Search	*s;
  class mfso	*mfsobj;
  int32_t	fd;	
  bool		locked;

public:
  class 	Node*  		node;

  VFile(int32_t fd, class mfso *mfsobj, class Node *node);
  ~VFile();
  EXPORT	int32_t 		close(void);

  pdata*		read(void);
  pdata*		read(uint32_t size);
  EXPORT	int32_t 		read(void *buff, uint32_t size);
  EXPORT	uint64_t 	seek(uint64_t offset, char *whence);
  EXPORT	uint64_t 	seek(uint64_t offset, int32_t whence);
  EXPORT    	uint64_t 	seek(uint64_t offset);
  EXPORT	uint64_t	seek(int32_t offset, int32_t whence);
  EXPORT	int32_t		write(string buff);
  EXPORT    	int32_t		write(char *buff, uint32_t size);

  EXPORT	list<uint64_t>	*search(char *needle, uint32_t len, char wildcard, uint64_t start = 0, uint64_t window = (uint64_t)-1, uint32_t count = (uint32_t)-1);

  EXPORT	uint64_t	find(char *needle, uint32_t len, char wildcard, uint64_t start=0, uint64_t window=(uint64_t)-1);

  EXPORT	uint64_t	rfind(char *needle, uint32_t len, char wildcard, uint64_t start=0, uint64_t window=(uint64_t)-1);

  EXPORT	uint32_t	count(char *needle, uint32_t len, char wildcard, uint64_t start=0, uint64_t window=(uint64_t)-1);

  EXPORT int32_t	dfileno();
  EXPORT uint64_t 	tell();
};

#endif
