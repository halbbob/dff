/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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
 *  Solal J. <sja@digital-forensic.org>
 */

#include "vfile.hpp"

VFile::VFile(int32_t fd, class fso *fsobj, class Node *node) 
{
  this->__search = new Search();
  this->__fd = fd;
  this->__fsobj = fsobj;
  this->__node = node;
};

VFile::~VFile()
{
  try
    {
      this->close();
    }
  catch (const vfsError& e)
    {
    }
  delete this->__search;
}

class Node*	VFile::node()
{
  return this->__node;
}

pdata* VFile::read(void)
{
  int32_t	n;
  pdata*	data;
  uint64_t	size;

  data = new pdata;
  size = this->__node->size();
  try
    {
      data->buff = malloc(size);
	  if (data->buff == NULL)
	     throw vfsError("VFile::read() can't allocate memory\n" + e.error);
      memset(data->buff, 0, size);
      n = this->__fsobj->vread(this->__fd, (void*)data->buff, size);
      data->len = n;
      return (data);
    }
  catch (vfsError e)
    {
      free(data->buff);
      delete data;
      throw vfsError("VFile::read() throw\n" + e.error);
    }
}

pdata* VFile::read(uint32_t size)
{
  int32_t	n;
  pdata*	data;

  data = new pdata;
  try
    {
      data->buff = malloc(size);
      data->len = size;
      memset(data->buff, 0, size);
      n = this->__fsobj->vread(this->__fd, data->buff, size);
      data->len = n;
      return (data);
    }
  catch (vfsError e)
    {
      free(data->buff);
      delete data;
      throw vfsError("VFile::read(size) throw\n" + e.error);
    }
}

int VFile::read(void *buff, uint32_t size)
{
  uint32_t n;

  try 
  {
    n = this->__fsobj->vread(this->__fd, buff, size);
    return (n);
  }
  catch (vfsError e)
  {
    throw vfsError("Vfile::read(buff, size) throw\n" + e.error); 
  }
}

uint64_t  VFile::seek(uint64_t offset, char *cwhence)
{
  int32_t	wh;
  string	whence = cwhence;

  if (whence == string("SET"))
    wh = 0;
  else if (whence == string("CUR"))
    wh = 1;
  else if (whence == string("END"))
    wh = 2;
  else
    throw vfsError("VFile::vseek(dff_ui64, char *) error whence not defined ( SET, CUR, END )");
  try
    {
      return (this->__fsobj->vseek(this->__fd, offset, wh));
    }
  catch (vfsError e)
    {
      throw vfsError("VFile::seek(dff_ui64, char*) throw\n" + e.error);
    }
}

uint64_t  VFile::seek(uint64_t offset, int32_t whence)
{
  if (whence > 2)
    throw vfsError("VFile::vseek(offset, whence) error whence not defined ( SET, CUR, END )");
  try
    {
      return (this->__fsobj->vseek(this->__fd, offset, whence));
    }
  catch (vfsError e)
    {
      throw vfsError("VFile::seek(dff_ui64, whence) throw\n" + e.error);
    }
}

uint64_t VFile::seek(uint64_t offset)
{
  try
    {
      return (this->__fsobj->vseek(this->__fd, offset, 0));
    }
  catch (vfsError e)
    {
      throw vfsError("VFile::seek(dff_ui64) throw\n" + e.error);
    }
}

uint64_t  VFile::seek(int32_t offset, int32_t whence)
{
  if (whence > 2)
    throw vfsError("VFile::vseek(offset, whence) error whence not defined ( SET, CUR, END )");
  try
    {
      return (this->__fsobj->vseek(this->__fd, (uint64_t)offset, whence));
    }
  catch (vfsError e)
    {
      throw vfsError("Vfile::seek(int offset, int whence) throw\n" + e.error);
    }
}

int32_t VFile::write(std::string buff)
{
  int32_t n;
   
  try 
    {
      n = this->__fsobj->vwrite(this->__fd, (void *)buff.c_str(), buff.size());
      return (n);
    }
  catch (vfsError e)
   {
     throw vfsError("VFile::write(string) throw\n" + e.error);
   }
}

int32_t VFile::write(char *buff, uint32_t size)
{
  int32_t n;
  
  try
    {
      n = this->__fsobj->vwrite(this->__fd, buff, size);
      return (n);
    }
  catch (vfsError e)
    {
      throw vfsError("VFile::write(buff, size) throw\n" + e.error);
    }
}

int32_t VFile::close(void)
{
  try 
    {
      if (this->__fd != -1)
	{
	  this->__fsobj->vclose(this->__fd);
	  this->__fd = -1;
	}
    }
  catch (vfsError e)
    {
    }
  return 0;
}

int32_t  VFile::dfileno()
{
  return (this->__fd);
}

uint64_t VFile::tell()
{  
      return (this->__fsobj->vtell(this->__fd));
}

list<uint64_t>	*VFile::search(char *needle, uint32_t len, char wildcard, uint64_t start, uint64_t window, uint32_t count)
{
  unsigned char			*buffer = (unsigned char*)malloc(sizeof(char) * BUFFSIZE);
  list<uint32_t>		*res;
  list<uint32_t>::iterator	it;
  list<uint64_t>		*real = new list<uint64_t>;
  int32_t			bytes_read;
  bool				stop;
  uint32_t			hslen;
  
  this->__search->setNeedle((unsigned char*)needle);
  this->__search->setNeedleSize(len);
  this->__search->setWildcard((unsigned char)wildcard);
  this->seek(start, 0);
  stop = false;
  while(((bytes_read = this->read(buffer, BUFFSIZE)) > 0) && !stop)
    {
      if (window != (uint64_t)-1)
	{
	  if (window < bytes_read)
	    {
	      hslen = window;
	      stop = true;
	    }
	  else
	    {
	      hslen = bytes_read;
	      window -= bytes_read;
	    }
	}
      else
	if (bytes_read < BUFFSIZE)
	  hslen = bytes_read;
	else
	  hslen = BUFFSIZE;
      if (count != (uint32_t)-1)
	{
	  res = this->__search->run(buffer, hslen, &count);
	  if (count == 0)
	    stop = true;
	}
      else
	res = this->__search->run(buffer, hslen);
      try  
      {
        for (it = res->begin(); it != res->end(); it++)
	  real->push_back(*it + this->tell() - bytes_read);
        if (bytes_read == BUFFSIZE)
	  this->seek(this->tell() - len, 0);
      }
      catch (vfsError &e)
	{}
      delete res;
    }
  free(buffer);
  return real;
}


uint64_t	VFile::find(char *needle, uint32_t len, char wildcard, uint64_t start, uint64_t window)
{
  list<uint64_t>	*l;
  uint64_t		res;

  l = this->search(needle, len, wildcard, start, window, 1);
  if (l->size() > 0)
    res = l->front();
  else
    res = uint64_t(-1);
  delete l;
  return res;
}

uint32_t	VFile::count(char *needle, uint32_t len, char wildcard, uint64_t start, uint64_t window)
{
  list<uint64_t>	*l;
  unsigned int		count;

  l = this->search(needle, len, wildcard, start, window);
  count = l->size();
  delete l;
  return count;
}
