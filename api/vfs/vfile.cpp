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

#include "vfile.hpp"

VFile::VFile(int32_t fd, class mfso *mfsobj, class Node *node) 
{
  this->s = new Search();
  this->fd = fd;
  this->mfsobj = mfsobj;
  this->node = node;
};

VFile::~VFile()
{
  std::cout << "deleting vfile" << std::endl;
  delete this->s;
}

int VFile::read(void *buff, uint32_t size)
{  
  uint32_t n;

  try 
  {
    n = this->mfsobj->vread(fd, buff, size);
    return (n);
  }
  catch (vfsError e)
  {
    throw vfsError("Vfile::read(buff, size) throw\n" + e.error); 
  }
}

pdata* VFile::read(void)
{
  int32_t n;
  pdata* data = new pdata;
  //data->buff = malloc(node->attr->size);
  //data->len = node->attr->size;
  try 
  {
    //n = this->mfsobj->vread(fd, (void*)data->buff, node->attr->size);
    //data->len = n;	
    return (data);
  }
  catch (vfsError e)
  {
    free(data->buff);
    free(data);
    throw vfsError("VFile::read() throw\n" + e.error);
  }
}

pdata* VFile::read(uint32_t size)
{
  int32_t n;
  pdata* data = new pdata;
  data->buff = malloc(size); 
  data->len = size;

  memset(data->buff, 0, size);
  try 
  { 
    n = this->mfsobj->vread(this->fd, data->buff, size);
    //std::cout << "returned read size " << n << std::endl;
    data->len = n;
    return (data);
  }
  catch (vfsError e)
  {
    free(data->buff);
    free(data);
    throw vfsError("VFile::read(size) throw\n" + e.error);
  }
}

int32_t VFile::close(void)
{
  try 
  {
    this->mfsobj->vclose(fd);
  }
  catch (vfsError e)
  {
     throw vfsError("Vfile::close() throw\n" + e.error);
  }
  return 0;
}


int32_t VFile::write(string buff)
{
  int32_t n;
   
  try 
    {
      n = this->mfsobj->vwrite(fd, (void *)buff.c_str(), buff.size());
      return (n);
    }
  catch (vfsError e)
   {
     throw vfsError("VFile::write(string) throw\n" + e.error);
   }
}

int32_t VFile::write(char *buff, unsigned int size)
{
  int32_t n;
  
  try 
    {
      n = this->mfsobj->vwrite(fd, buff, size);
      return (n);
    }
  catch (vfsError e)
    {
      throw vfsError("VFile::write(buff, size) throw\n" + e.error);
    }
}

uint64_t VFile::seek(uint64_t offset)
{
  try
  {
    return (this->mfsobj->vseek(fd, offset, 0));
  }
  catch (vfsError e)
  {
    throw vfsError("VFile::seek(dff_ui64) throw\n" + e.error);
  }
}

uint64_t  VFile::seek(uint64_t offset, char *cwhence)
{
  int32_t wh;
  string whence = cwhence;

  if (whence == string("SET"))
    wh = 0;
  else if (whence == string("CUR"))
    wh = 1;
  else if (whence == string("END"))
    wh = 2;
  else
    {
      throw vfsError("VFile::vseek(dff_ui64, char *) error whence not defined ( SET, CUR, END )");
    }
  try
    { 
      return (this->mfsobj->vseek(fd, offset, wh));
    }
  catch (vfsError e)
    {
      throw vfsError("VFile::seek(dff_ui64, char*) throw\n" + e.error);
    }
}

uint64_t  VFile::seek(uint64_t offset, int32_t whence)
{
  if (whence > 2)
    {
      throw vfsError("VFile::vseek(offset, whence) error whence not defined ( SET, CUR, END )");
      return 0;
    }
  try
    {
      return (this->mfsobj->vseek(fd, offset, whence));
    }
  catch (vfsError e)
    {
      throw vfsError("VFile::seek(dff_ui64, whence) throw\n" + e.error);
    }
}

uint64_t  VFile::seek(int32_t offset, int32_t whence)
{
  if (whence > 2)
    {
      throw vfsError("VFile::vseek(offset, whence) error whence not defined ( SET, CUR, END )");
      return 0;
    }
  try
    {
      return (this->mfsobj->vseek(fd, (long long)offset, whence));
    }
  catch (vfsError e)
  {
    throw vfsError("Vfile::seek(int offset, int whence) throw\n" + e.error);
  }
 
}

int32_t  VFile::dfileno()
{
  return (fd);
}

uint64_t VFile::tell()
{  
  try
    {
      return (this->mfsobj->vtell(this->fd));
    }
  catch (vfsError e)
    {
      throw vfsError("VFile::tell() throw\n" + e.error);
    }
}

list<uint64_t>	*VFile::search(char *needle, uint32_t len, char wildcard, uint64_t start, uint64_t window, uint32_t count)
{
  //class Search	*s = new class Search((unsigned char*)needle, len, (unsigned char)wildcard);
  unsigned char *buffer = (unsigned char*)malloc(sizeof(char) * BUFFSIZE);
  list<uint32_t>		*res;
  list<uint32_t>::iterator	it;
  list<uint64_t>	*real = new list<uint64_t>;
  int32_t			bytes_read;
  bool				stop;
  uint32_t			hslen;
  
  s->setNeedle((unsigned char*)needle);
  s->setNeedleSize(len);
  s->setWildcard((unsigned char)wildcard);
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
	hslen = BUFFSIZE;
      if (count != (uint32_t)-1)
	{
	  res = s->run(buffer, hslen, &count);
	  if (count == 0)
	    stop = true;
	}
      else
	res = s->run(buffer, hslen);
      for (it = res->begin(); it != res->end(); it++)
	real->push_back(*it + this->tell() - bytes_read);
      if (bytes_read == BUFFSIZE)
	this->seek(this->tell() - len, 0);
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
    res = dff_ui64(-1);
  delete l;
  return res;
}

uint64_t	VFile::rfind(char *needle, uint32_t len, char wildcard, uint64_t start, uint64_t window)
{
  return 0;
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
