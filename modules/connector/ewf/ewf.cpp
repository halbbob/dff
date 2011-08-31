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
 *  Solal Jacob <sja@digital-forensic.org>
 */

#include "ewf.hpp"
#include "ewfnode.hpp"


ewf::ewf() : fso("ewf")
{
  this->__fdm = new FdManager();
  this->ewf_ghandle = NULL;
  this->__ewf_error = NULL;
  this->files = NULL;
}

ewf::~ewf()
{
  this->__cleanup();
}

void	ewf::__cleanup()
{
  if (this->__ewf_error != NULL)
    {
      libewf_error_free(&this->__ewf_error);
      this->__ewf_error = NULL;
    }
  if (this->ewf_ghandle != NULL)
    {
      libewf_handle_close(this->ewf_ghandle, NULL);
      libewf_handle_free(&this->ewf_ghandle, NULL);
      this->ewf_ghandle = NULL;
    }
  if (this->files != NULL)
    {
      this->files = NULL;
      free(this->files);
    }
}

void	ewf::__checkSignature(std::list<Variant*> vl) throw (std::string)
{
  std::list<Variant *>::iterator	vpath;
  std::string				err;
  char*					cerr;
  
  this->files = (char**)malloc(sizeof(char*) * (vl.size() + 1));
  this->nfiles = 0;
  for (vpath = vl.begin(); vpath != vl.end(); vpath++)
    {
      std::string path = (*vpath)->value<Path* >()->path;
      if (libewf_check_file_signature(path.c_str(), &this->__ewf_error) == 1)
	{
	  this->files[nfiles] = strdup((char*)path.c_str());
	  this->nfiles++;
	}
      else
	{
	  if (this->__ewf_error != NULL)
	    {
	      cerr = new char[512];
	      libewf_error_backtrace_sprint(this->__ewf_error, cerr, 511);
	      err = std::string(cerr);
	    }
	  else
	    {
	      std::ostringstream error;
	      
	      error << "file " << path << " is not a ewf file." << endl;
	      err = error.str();
	    }
	  throw (err);
	}
    }
  this->files[nfiles] = NULL;
  return ;
}

void	ewf::__initHandle(libewf_handle_t** handle, libewf_error_t** error) throw (std::string)
{
  std::string	err;
  char*		cerr;

  if (libewf_handle_initialize(handle, error) != 1)
    {
      if (error != NULL)
	{
	  cerr = new char[512];
	  libewf_error_backtrace_sprint(*error, cerr, 511);
	  err = std::string(cerr);
	  delete cerr;
	}
      else
	err = std::string("Ewf: Unable to initialize handle");
      throw (err);
    }
  return;
}

void	ewf::__openHandle(libewf_handle_t* handle, libewf_error_t** error) throw (std::string)
{
  std::string				err;
  char*					cerr;

  if (libewf_handle_open(handle, this->files, this->nfiles, LIBEWF_OPEN_READ, error) != 1)
    {
      if (error != NULL)
	{
	  cerr = new char[512];
	  libewf_error_backtrace_sprint(*error, cerr, 511);
	  err = std::string(cerr);
	}
      else
	err = std::string("Can't open EWF files");
      throw (err);
    }
  return;
}


void	ewf::__getVolumeName()
{
  uint8_t*	value;
  size_t	val_size;
  std::string	volume;
 
  if (libewf_handle_get_utf8_header_value_size(this->ewf_ghandle, (uint8_t*)"description", 11, &val_size, &this->__ewf_error) != 1)
    this->volumeName = std::string("ewf_volume");
  else
    {
      value = new uint8_t[val_size];
      if (libewf_handle_get_utf8_header_value(this->ewf_ghandle, (uint8_t*)"description", 11, value, val_size, &this->__ewf_error) == 1)
	this->volumeName = std::string((char*)value, val_size-1);
      else
	this->volumeName = std::string("ewf_volume");
      delete value;
    }
  return;
}

void	ewf::__getVolumeSize() throw (std::string)
{
  std::string	err;
  
  if (libewf_handle_get_media_size(this->ewf_ghandle, &this->volumeSize, &this->__ewf_error) != 1)
    {
      if (this->__ewf_error != NULL)
	{
	  char*	cerr = new char[512];
	  libewf_error_backtrace_sprint(this->__ewf_error, cerr, 511);
	  err = std::string(cerr);
	}
      else
	err = std::string("Can't get EWF dump size.");
      throw (err);
    }
  return;
}

void ewf::start(std::map<std::string, Variant* > args)
{
  std::list<Variant *>	vl;
  EWFNode*		ewfNode;

  if (args["parent"])
    this->parent = args["parent"]->value<Node* >();
  else
    this->parent = VFS::Get().GetNode("/");
  if (args["files"])
    vl = args["files"]->value<std::list<Variant* > >();
  else
    throw(envError("ewf module requires path argument"));  
  
  try
    {
      this->__initHandle(&this->ewf_ghandle, &this->__ewf_error);
      this->__checkSignature(vl);
      this->__openHandle(this->ewf_ghandle, &this->__ewf_error);
      this->__getVolumeSize();
      this->__getVolumeName();
      ewfNode = new EWFNode(this->volumeName, this->volumeSize, NULL, this, vl);
      this->registerTree(this->parent, ewfNode);
    }
  catch (std::string err)
    {
      this->__cleanup();
      this->res["error"] = new Variant(err);
    }
  return ;
}

int ewf::vopen(Node *node)
{
  libewf_handle_t* ewf_handle = NULL;

  try
    {
      this->__initHandle(&ewf_handle, NULL);
      this->__openHandle(ewf_handle, NULL);
    }
  catch (std::string err)
    {
      return -1;
    }
  fdinfo* fi = new fdinfo();
  fi->node = node;
  fi->offset = 0;
  fi->id = new Variant((void*)ewf_handle);
  return (this->__fdm->push(fi));
}

int ewf::vread(int fd, void *buff, unsigned int size)
{
  fdinfo*		fi;
  libewf_handle_t* 	ewf_handle; 

  try
  {
    fi = this->__fdm->get(fd);
    ewf_handle = (libewf_handle_t*)fi->id->value<void *>();
  }
  catch (...)
  {
    return (0);
  }
  int res = 0;
  res = libewf_handle_read_buffer(ewf_handle, buff, size, NULL);
  if (res < 0)
    return (0);
  return (res);
}

int ewf::vclose(int fd)
{
  fdinfo*		fi;
  libewf_handle_t* 	ewf_handle; 

  try 
  {
    fi = this->__fdm->get(fd);
    ewf_handle = (libewf_handle_t*)fi->id->value<void *>();
  }
  catch (...)
  {
    return (-1);
  }
  if (ewf_handle != NULL)
    {
      libewf_handle_close(ewf_handle, NULL);
      libewf_handle_free(&ewf_handle, NULL);
    }
  delete fi->id;
  this->__fdm->remove(fd);
  return -1;
}

uint64_t ewf::vseek(int fd, uint64_t offset, int whence)
{
  fdinfo*		fi;
  libewf_handle_t* 	ewf_handle; 

  try 
  {
    fi = this->__fdm->get(fd);
    ewf_handle = (libewf_handle_t*)fi->id->value<void *>();
    return (libewf_handle_seek_offset(ewf_handle, offset, whence, NULL));
  }
  catch (...)
    {
      return (-1);
    }
  return (-1);
}

uint64_t	ewf::vtell(int32_t fd)
{
  fdinfo*		fi;
  libewf_handle_t* 	ewf_handle;
  int64_t		offset;

  try 
  {
    fi = this->__fdm->get(fd);
    ewf_handle = (libewf_handle_t*)fi->id->value<void *>();
  }
  catch (...)
  {
    return (-1);
  }
  if (libewf_handle_get_offset(ewf_handle, &offset, NULL) == -1)
    return (uint64_t)-1;
  else if (offset >= 0)
    return (uint64_t)offset;
  else
    return (uint64_t)-1;
}

unsigned int ewf::status(void)
{
  return (0);
}
