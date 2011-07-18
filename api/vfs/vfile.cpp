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
  this->__fs = new FastSearch();
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
  delete this->__fs;
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
	     throw vfsError("VFile::read() can't allocate memory\n");
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

std::string  VFile::readline(uint32_t size) throw (std::string)
{
  std::string		res;
  unsigned char*	buffer;
  uint32_t		bread;
  uint32_t		bsize;
  uint32_t		consumed;
  uint32_t		i;
  uint64_t		oldoff;
  bool			found;

  if (size == 0)
    size = INT32_MAX;
  if (size < 300)
    bsize = size;
  else
    bsize = 300;
  res = "";
  oldoff = this->tell();
  if ((buffer = (unsigned char*)malloc(bsize)) != NULL)
    {
      consumed = 0;
      found = false;
      while (((bread = this->read(buffer, bsize)) > 0) && (consumed != size) && (!found))
	{
	  i = 0;
	  while ((i != bread) && (consumed != size) && (!found))
	    {
	      res += buffer[i];
	      consumed += 1;
	      if (buffer[i] == '\n')
		found = true;
	      i++;
	    }
	}
      this->seek(oldoff+consumed);
      //std::cout << "oldoff: " << oldoff << " -- consumed: " << consumed << " -- rsize: " << res.size() << std::endl << "move to: " << this->tell() << std::endl;
      free(buffer);
    }
  else
    throw(std::string("VFile::readline() --> malloc failed"));
  return res;
}

int64_t		VFile::find(unsigned char* needle, uint32_t nlen, unsigned char wildcard, uint64_t start, uint64_t end) throw (std::string)
{
  unsigned char		*buffer;
  int32_t		bread;
  int32_t		idx;
  int32_t		hlen;
  uint64_t		totalread;
  int64_t		pos;

  if (end > this->__node->size())
    end = this->__node->size();
  if ((end != 0) && (end < start))
    throw std::string("VFile::find 'end' argument must be greater than 'start' argument");
  if (nlen == 0)
    return 0;
  idx = -1;
  totalread = this->seek(start);
  buffer = (unsigned char*)malloc(sizeof(char) * BUFFSIZE);
  while (((bread = this->read(buffer, BUFFSIZE)) > 0) && (totalread < end) && (idx == -1))
    {
      if (end < totalread + bread)
	hlen = (int32_t)(end - totalread);
      else
	hlen = bread;
      idx = this->__fs->find(buffer, hlen, needle, nlen, wildcard);
      if (idx == -1)
	{
	  if (hlen == BUFFSIZE)
	    totalread = this->seek(this->tell() - nlen);
	  else
	    totalread = this->seek(this->tell());
	}
    }
  free(buffer);
  if (idx == -1)
    pos = -1;
  else
    pos = totalread + idx;
  return pos;
}


int64_t		VFile::rfind(unsigned char* needle, uint32_t nlen, unsigned char wildcard, uint64_t start, uint64_t end) throw (std::string)
{
  unsigned char		*buffer;
  int32_t		bread;
  int32_t		idx;
  int32_t		hlen;
  uint64_t		rpos;
  int64_t		pos;

  if (end > this->__node->size())
    end = this->__node->size();
  if ((end != 0) && (end < start))
    throw std::string("VFile::rfind 'end' argument must be greater than 'start' argument");
  if (nlen == 0)
    return 0;
  idx = -1;
  buffer = (unsigned char*)malloc(sizeof(char) * BUFFSIZE);
  if (end < start + BUFFSIZE)
    {
      rpos = this->seek(start);
      bread = this->read(buffer, end-start);
      idx = this->__fs->rfind(buffer, bread, needle, nlen, wildcard);
    }
  else
    {
      rpos = end-BUFFSIZE;
      this->seek(rpos);
      while (((bread = this->read(buffer, BUFFSIZE)) > 0) && (rpos > start) && (idx == -1))
      	{
      	  if (rpos < start + bread)
      	    hlen = (int32_t)(rpos - start);
      	  else
      	    hlen = bread;
      	  idx = this->__fs->rfind(buffer, hlen, needle, nlen, wildcard);
      	  if (idx == -1)
	    {
	      if (hlen == BUFFSIZE)
		rpos = this->seek(rpos - hlen + nlen);
	      else
		rpos = this->seek(rpos - hlen);
	    }
      	}
    }
  free(buffer);
  if (idx == -1)
    pos = -1;
  else
    pos = rpos + idx;
  return pos;
}


int32_t		VFile::count(unsigned char* needle, uint32_t nlen, unsigned char wildcard, int32_t maxcount, uint64_t start, uint64_t end) throw (std::string)
{
  unsigned char		*buffer;
  int32_t		bread;
  uint64_t		totalread;
  int32_t		tcount;
  int32_t		count;
  int32_t		hlen;

  if (end > this->__node->size())
    end = this->__node->size();
  if ((end != 0) && (end < start))
    throw std::string("VFile::count 'end' argument must be greater than 'start' argument");
  if (nlen == 0)
    {
      if (start == 0)
	return (end + 1);
      else
	return (end - start + 1);
    }
  buffer = (unsigned char*)malloc(sizeof(char) * BUFFSIZE);
  count = 0;
  totalread = this->seek(start);
  while (((bread = this->read(buffer, BUFFSIZE)) > 0) && (totalread < end) && (maxcount > 0))
    {
      if (end < totalread + bread)
	hlen = (int32_t)(end - totalread);
      else
	hlen = bread;
      tcount = this->__fs->count(buffer, hlen, needle, nlen, wildcard, maxcount);
      if (tcount > 0)
	{
	  count += tcount;
	  maxcount -= tcount;
	}
      if ((hlen == BUFFSIZE) && (this->__fs->find(buffer+(BUFFSIZE-nlen), nlen, needle, nlen, wildcard) != -1))
	totalread = this->seek(this->tell() - nlen);
      else
	totalread = this->seek(this->tell());
    }
  free(buffer);
  return count;
}


std::list<uint64_t>	VFile::indexes(unsigned char* needle, uint32_t nlen, unsigned char wildcard, uint64_t start, uint64_t end) throw (std::string)
{
  unsigned char		*buffer;
  std::list<uint64_t>	indexes;
  int32_t		bread;
  int32_t		idx;
  int32_t		buffpos;
  uint64_t		totalread;
  int32_t		hlen;

  if (end > this->__node->size())
    end = this->__node->size();
  if ((end != 0) && (end < start))
    throw std::string("VFile::indexes 'end' argument must be greater than 'start' argument");
  if (nlen == 0)
    return indexes;
  totalread = this->seek(start);
  buffer = (unsigned char*)malloc(sizeof(char) * BUFFSIZE);
  event*	e = new event;
  while (((bread = this->read(buffer, BUFFSIZE)) > 0) && (totalread < end))
    {
      buffpos = 0;
      if (end < totalread + bread)
	hlen = (int32_t)(end - totalread);
      else
	hlen = bread;
      while ((buffpos < hlen - (int32_t)nlen) && ((idx = this->__fs->find(buffer+buffpos, hlen - buffpos, needle, nlen, wildcard)) != -1))
	{
	  buffpos += idx + nlen;
	  indexes.push_back(this->tell() - bread + buffpos - nlen);
	}
      if ((hlen == BUFFSIZE) && (buffpos != hlen))
	totalread = this->seek(this->tell() - nlen);
      else
	totalread = this->seek(this->tell());
      
      e->value = new Variant(totalread);
      this->notify(e);
    }
  free(buffer);
  return indexes;
}


int64_t			VFile::find(std::string needle, unsigned char wildcard, uint64_t start, uint64_t end) throw (std::string)
{
  int64_t		ret;

  try
    {
      ret = this->find((unsigned char*)needle.c_str(), needle.size(), wildcard, start, end);
      return ret;
    }
  catch (std::string e)
    {
      throw e;
    }
}

int64_t			VFile::rfind(std::string needle, unsigned char wildcard, uint64_t start, uint64_t end) throw (std::string)
{
  int64_t		ret;

  try
    {
      ret = this->rfind((unsigned char*)needle.c_str(), needle.size(), wildcard, start, end);
      return ret;
    }
  catch (std::string e)
    {
      throw e;
    }
}

int32_t			VFile::count(std::string needle, unsigned char wildcard, int32_t maxcount, uint64_t start, uint64_t end) throw (std::string)
{
  int32_t		ret;

  try
    {
      ret = this->count((unsigned char*)needle.c_str(), needle.size(), wildcard, maxcount, start, end);
      return ret;
    }
  catch (std::string e)
    {
      throw e;
    }
}

std::list<uint64_t>	VFile::indexes(std::string needle, unsigned char wildcard, uint64_t start, uint64_t end) throw (std::string)
{
  std::list<uint64_t>	ret;

  try
    {
      ret = this->indexes((unsigned char*)needle.c_str(), needle.size(), wildcard, start, end);
      return ret;
    }
  catch (std::string e)
    {
      throw e;
    }
}


/* The following method is only for backward compatibility */
std::list<uint64_t>*	VFile::search(char* needle, uint32_t nlen, unsigned char wildcard, uint64_t start, uint64_t end) throw (std::string)
{
  std::list<uint64_t>*	ret;
  
  try
    {
      ret = new std::list<uint64_t>(this->indexes((unsigned char*)needle, nlen, wildcard, start, end));
      return ret;
    }
  catch (std::string e)
    {
      throw e;
    }
}


/* Following methods will be part of the future API.
Use the ones from now as they'll become default.
*/

int64_t		VFile::find(Search* sctx, uint64_t start, uint64_t end) throw (std::string)
{
  unsigned char		*buffer;
  int32_t		bread;
  int32_t		idx;
  int32_t		hlen;
  uint64_t		totalread;
  int64_t		pos;
  uint32_t		nlen;

  if (sctx == NULL)
    throw (std::string("VFile::find, Search context is not set."));
  if (end > this->__node->size())
    end = this->__node->size();
  if ((end != 0) && (end < start))
    throw std::string("VFile::find 'end' argument must be greater than 'start' argument");
  idx = -1;
  totalread = this->seek(start);
  buffer = (unsigned char*)malloc(sizeof(char) * BUFFSIZE);
  nlen = sctx->needleLength();
  while (((bread = this->read(buffer, BUFFSIZE)) > 0) && (totalread < end) && (idx == -1))
    {
      if (end < totalread + bread)
	hlen = (int32_t)(end - totalread);
      else
	hlen = bread;
      try
	{
	  idx = sctx->find((char*)buffer, hlen);
	}
      catch (std::string err)
	{
	  if (buffer != NULL)
	    free(buffer);
	  throw (err);
	}
      if (idx == -1)
	{
	  if (hlen == BUFFSIZE)
	    totalread = this->seek(this->tell() - nlen);
	  else
	    totalread = this->seek(this->tell());
	}
    }
  free(buffer);
  if (idx == -1)
    pos = -1;
  else
    pos = totalread + idx;
  return pos;
}


int64_t		VFile::rfind(Search* sctx, uint64_t start, uint64_t end) throw (std::string)
{
  unsigned char		*buffer;
  int32_t		bread;
  int32_t		idx;
  int32_t		hlen;
  uint64_t		rpos;
  int64_t		pos;
  uint32_t		nlen;

  if (sctx == NULL)
    throw (std::string("VFile::rfind, Search context is not set."));
  if (end > this->__node->size())
    end = this->__node->size();
  if ((end != 0) && (end < start))
    throw std::string("VFile::rfind 'end' argument must be greater than 'start' argument");
  idx = -1;
  buffer = (unsigned char*)malloc(sizeof(char) * BUFFSIZE);
  nlen = sctx->needleLength();
  if (end < start + BUFFSIZE)
    {
      rpos = this->seek(start);
      bread = this->read(buffer, end-start);
      try
	{
	  idx = sctx->rfind((char*)buffer, bread);
	}
      catch (std::string err)
	{
	  throw (err);
	}
    }
  else
    {
      rpos = end-BUFFSIZE;
      this->seek(rpos);
      while (((bread = this->read(buffer, BUFFSIZE)) > 0) && (rpos > start) && (idx == -1))
      	{
      	  if (rpos < start + bread)
      	    hlen = (int32_t)(rpos - start);
      	  else
      	    hlen = bread;
	  try
	    {
	      idx = sctx->rfind((char*)buffer, hlen);
	    }
	  catch (std::string err)
	    {
	      if (buffer != NULL)
		free(buffer);
	      throw (err);
	    }
      	  if (idx == -1)
	    {
	      if (hlen == BUFFSIZE)
		rpos = this->seek(rpos - hlen + nlen);
	      else
		rpos = this->seek(rpos - hlen);
	    }
      	}
    }
  free(buffer);
  if (idx == -1)
    pos = -1;
  else
    pos = rpos + idx;
  return pos;
}


int32_t		VFile::count(Search* sctx, int32_t maxcount, uint64_t start, uint64_t end) throw (std::string)
{
  unsigned char		*buffer;
  int32_t		bread;
  uint64_t		totalread;
  int32_t		tcount;
  int32_t		count;
  int32_t		hlen;
  uint32_t		nlen;

  if (sctx == NULL)
    throw (std::string("VFile::count, Search context is not set."));
  if (end > this->__node->size())
    end = this->__node->size();
  if ((end != 0) && (end < start))
    throw std::string("VFile::count 'end' argument must be greater than 'start' argument");
  buffer = (unsigned char*)malloc(sizeof(char) * BUFFSIZE);
  count = 0;
  totalread = this->seek(start);
  nlen = sctx->needleLength();
  while (((bread = this->read(buffer, BUFFSIZE)) > 0) && (totalread < end) && (maxcount > 0))
    {
      if (end < totalread + bread)
	hlen = (int32_t)(end - totalread);
      else
	hlen = bread;
      try
	{
	  if (buffer != NULL)
	    free(buffer);
	  tcount = sctx->count((char*)buffer, hlen, maxcount);
	}
      catch (std::string err)
	{
	  throw (err);
	}
      if (tcount > 0)
	{
	  count += tcount;
	  maxcount -= tcount;
	}
      if ((hlen == BUFFSIZE) && (sctx->find((char*)(buffer+(BUFFSIZE-nlen)), nlen) != -1))
	totalread = this->seek(this->tell() - nlen);
      else
	totalread = this->seek(this->tell());
    }
  free(buffer);
  return count;
}


std::list<uint64_t>	VFile::indexes(Search* sctx, uint64_t start, uint64_t end) throw (std::string)
{
  unsigned char		*buffer;
  std::list<uint64_t>	indexes;
  int32_t		bread;
  int32_t		idx;
  int32_t		buffpos;
  uint64_t		totalread;
  int32_t		hlen;
  uint32_t		nlen;

  if (sctx == NULL)
    throw (std::string("VFile::indexes, Search context is not set."));
  if (end > this->__node->size())
    end = this->__node->size();
  if ((end != 0) && (end < start))
    throw std::string("VFile::indexes 'end' argument must be greater than 'start' argument");
  totalread = this->seek(start);
  buffer = (unsigned char*)malloc(sizeof(char) * BUFFSIZE);
  event*	e = new event;
  nlen = sctx->needleLength();
  while (((bread = this->read(buffer, BUFFSIZE)) > 0) && (totalread < end))
    {
      buffpos = 0;
      if (end < totalread + bread)
	hlen = (int32_t)(end - totalread);
      else
	hlen = bread;
      try
	{
	  while ((buffpos < hlen - (int32_t)nlen) && ((idx = sctx->find((char*)(buffer+buffpos), hlen - buffpos)) != -1))
	    {
	      nlen = sctx->needleLength();
	      buffpos += idx + nlen;
	      indexes.push_back(this->tell() - bread + buffpos - nlen);
	    }
	}
      catch (std::string err)
	{
	  if (buffer != NULL)
	    free(buffer);
	}
      if ((hlen == BUFFSIZE) && (buffpos != hlen))
	totalread = this->seek(this->tell() - nlen);
      else
	totalread = this->seek(this->tell());
      
      e->value = new Variant(totalread);
      this->notify(e);
    }
  free(buffer);
  return indexes;
}
