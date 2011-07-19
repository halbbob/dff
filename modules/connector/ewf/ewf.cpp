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
}

ewf::~ewf()
{
   libewf_close(this->ewf_ghandle);
   free(this->files);
}

void ewf::start(std::map<std::string, Variant* > args)
{
  std::list<Variant *> vl; 
  std::list<Variant *>::iterator 		 vpath; 

  if (args["parent"])
    this->parent = args["parent"]->value<Node* >();
  else
    this->parent = VFS::Get().GetNode("/");
  if (args["files"])
    vl = args["files"]->value<std::list<Variant* > >();
  else
    throw(envError("ewf module requires path argument"));  


  this->files = (char**)malloc(sizeof(char*) * (vl.size() + 1));
  this->nfiles = 0;
 
  for (vpath = vl.begin(); vpath != vl.end(); vpath++)
  {
     std::string path = (*vpath)->value<Path* >()->path;
     if (libewf_check_file_signature(path.c_str()) == 1)     
     {
	files[nfiles] = (char*)path.c_str();
	nfiles++;
     }
     else
     {
	std::ostringstream error;

	error << "file " << path << "is not a ewf file." << endl;
        Variant* verror = new Variant(error.str());
        this->res["error"] = verror;
 	return ;
     }
   }   

   files[nfiles] = NULL; 
   this->ewf_ghandle = libewf_open(this->files, this->nfiles, 1);
   if (this->ewf_ghandle == NULL)
   {
     this->res["error"] = new Variant(std::string("Can't open EWF files")); 
     return ;	   
   }

   this->volumeSize = 0; 
   if (libewf_get_media_size(this->ewf_ghandle, &volumeSize) == -1)
   {
	this->res["error"] = new Variant(std::string("Can't get EWF dump size."));
	return ; 
   }
 
   char* name = (char*) malloc(sizeof(char) * 1024);
   std::string volumeName;

   int	res = 0;
   res = libewf_get_header_value_description(this->ewf_ghandle, name, 1024);
   if (res == -1 || std::string(name) == "")
     volumeName = std::string("ewf");
   else
     volumeName = std::string(name);

   free(name);

   EWFNode* ewfNode = new EWFNode(volumeName, this->volumeSize, NULL, this, vl);
   this->registerTree(this->parent, ewfNode);

   return ;
}

int ewf::vopen(Node *node)
{
  libewf_handle_t* ewf_handle = libewf_open(this->files, this->nfiles, 1);
  if (ewf_handle == NULL)
    return (-1);

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
  res = libewf_read_buffer(ewf_handle, buff, size);
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
  return (libewf_close(ewf_handle));
}

uint64_t ewf::vseek(int fd, uint64_t offset, int whence)
{
  fdinfo*		fi;
  libewf_handle_t* 	ewf_handle; 
  

  try 
  {
    fi = this->__fdm->get(fd);
    ewf_handle = (libewf_handle_t*)fi->id->value<void *>();

    uint64_t	current_offset = libewf_get_offset(ewf_handle);
    if (whence == 0)
    {
      if (offset <= this->volumeSize)
      {
         return (libewf_seek_offset(ewf_handle, offset));
      }
    }
    else if (whence == 1)
    {
      if (current_offset + offset <= this->volumeSize)
        return (libewf_seek_offset(ewf_handle, offset + current_offset));
    }	
    else if (whence == 2)
    {
       return libewf_seek_offset(ewf_handle, this->volumeSize); 
    }

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

  try 
  {
    fi = this->__fdm->get(fd);
    ewf_handle = (libewf_handle_t*)fi->id->value<void *>();
  }
  catch (...)
  {
    return (-1);
  }

  return (libewf_get_offset(ewf_handle));
}

unsigned int ewf::status(void)
{
  return (0);
}
