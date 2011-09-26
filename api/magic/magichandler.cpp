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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include "magichandler.hpp"

MagicType::MagicType(std::string name, int flags) throw (std::string): DataTypeHandler(name)
{
  this->_ready = false;
  if ((this->_ctx = magic_open(flags)) == NULL)
    throw std::string("magic_open failed");
  if ((this->_buff = malloc(8192)) == NULL)
    throw std::string("cannot allocate memory");
}

MagicType::~MagicType()
{
  if (this->_ctx != NULL)
    magic_close(this->_ctx);
  if (this->_buff != NULL)
    free(this->_buff);
}

bool	MagicType::setMagicFile(std::string mfile) throw (std::string)
{
  const	char*	ecstr;
  std::string	estr;
  const char*	filename;

  this->_mfile = mfile;
  if (this->_mfile.empty())
    filename = NULL;
  else
    filename = this->_mfile.c_str();
  if (magic_load(this->_ctx, filename) == -1)
    {
      this->_ready = false;
      estr = "magic_load failed";
      if ((ecstr = magic_error(this->_ctx)) != NULL)
	estr += " : " + std::string(ecstr);
      throw estr;
    }
  else
    this->_ready = true;
  return this->_ready;
}

std::string	MagicType::magicFile()
{
  return this->_mfile;
}


MagicHandler*	MagicHandler::Get() throw (std::string)
{
  static MagicHandler single;
  return &single;
}

std::string	MagicHandler::type(Node* node)
{
  VFile*	vf;
  int32_t	rbytes;
  const char*	magic;
  std::string	res;

  res = std::string("None");
  vf = NULL;
  if (node != NULL && this->_ready)
    {
      if (node->size() > 0)
	{
	  try
	    {
	      if (((vf = node->open()) != NULL) && 
		  ((rbytes = vf->read(this->_buff, 8192)) > 0) && 
		  ((magic = magic_buffer(this->_ctx, this->_buff, rbytes)) != NULL))
		res = std::string(magic);
	    }
	  catch (vfsError e)
	    {
	    }
	}
      else if (node->hasChildren())
	res = std::string("directory");
      else
	res = std::string("empty");
    }
  if (vf != NULL)
    delete vf;
  return res;
}


MimeHandler*	MimeHandler::Get() throw (std::string)
{
  static MimeHandler single;
  return &single;
}

std::string	MimeHandler::type(Node* node)
{
  VFile*	vf;
  int32_t	rbytes;
  const char*	magic;
  std::string	res;

  res = std::string("None");
  vf = NULL;
  if (node != NULL && this->_ready)
    {
      if (node->size() > 0)
	{
	  try
	    {
	      if (((vf = node->open()) != NULL) && 
		  ((rbytes = vf->read(this->_buff, 8192)) > 0) && 
		  ((magic = magic_buffer(this->_ctx, this->_buff, rbytes)) != NULL))
		res = std::string(magic);
	    }
	  catch (vfsError e)
	    {
	    }
	}
      else if (node->hasChildren())
	res = std::string("application/x-directory; charset=binary");
      else
	res = std::string("application/x-empty; charset=binary");
    }
  if (vf != NULL)
    delete vf;
  return res;
}
