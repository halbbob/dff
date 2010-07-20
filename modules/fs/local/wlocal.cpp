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
 *  Christophe Malinge <cma@digital-forensic.org>
 */

#include "local.hpp"
#include <String>
#include <windows.h>
#include <shlwapi.h>

void				local::frec(const char *name, Node *rfv)
{
  HANDLE			hd;
  WIN32_FIND_DATAA	find;
  std::string		nname;
  std::string		searchPath = name;
  s_ull				sizeConverter;
	
  searchPath +=  "\\*";  
  
  if ((hd = FindFirstFileA(searchPath.c_str(), &find)) != INVALID_HANDLE_VALUE) {
    do {
	  WLocalNode	*tmp; //= new Node;
	  std::string	handle;
	  
	  if (!strcmp(find.cFileName, ".") || !strcmp(find.cFileName, ".."))
	    continue ;
	  nname = name;
	  nname += "\\";
	  nname += find.cFileName;
	  handle += nname;

	  if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		// Create a virtual directory
		tmp = new WLocalNode(find.cFileName, 0, rfv, this, WLocalNode::DIR);
		tmp->setBasePath(this->basePath.c_str());
		this->frec((char *)nname.c_str(), tmp);
	  }
	  else {
		// Create a virtual file
		sizeConverter.Low = find.nFileSizeLow;
		sizeConverter.High = find.nFileSizeHigh;
		tmp = new WLocalNode(find.cFileName, sizeConverter.ull, rfv, this, WLocalNode::FILE);
		tmp->setBasePath(this->basePath.c_str());
	  }
	} while (FindNextFileA(hd, &find));
    
    FindClose(hd);
  }
}

local::local(): mfso("local")
{
}

local::~local()
{
}

void						local::start(argument *arg)
{
  std::string				path;
  Path						*lpath;
  WIN32_FILE_ATTRIBUTE_DATA	info;
  s_ull						sizeConverter;
  
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
  while (lpath->path.find('/') != std::string::npos) {
	lpath->path[lpath->path.find('/')] = '\\';
  }
  
  if ((lpath->path.rfind('/') + 1) == lpath->path.length())
    lpath->path.resize(lpath->path.rfind('/'));
  if ((lpath->path.rfind('\\') + 1) == lpath->path.length())
    lpath->path.resize(lpath->path.rfind('\\'));
  path = lpath->path;
  if (path.rfind("\\") <= path.size())
    path = path.substr(path.rfind("\\") + 1);
  else 
    path = path.substr(path.rfind("/") + 1);
  if(!GetFileAttributesExA(lpath->path.c_str(), GetFileExInfoStandard, &info))
  {
	  res->add_const("error", string("error stating file:" + path)); 
      return ;
  }
  if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
  {
	// Create a virtual directory
	WLocalNode	*__root = new WLocalNode(path, 0, NULL, this, WLocalNode::DIR);
	
	this->basePath = lpath->path.substr(0, lpath->path.rfind('\\'));
    __root->setBasePath(this->basePath.c_str());
    this->_root = __root;
    //recurse
	this->frec(lpath->path.c_str(), this->_root);
  }
  else 
  {
	// Create a virtual file
	sizeConverter.Low = info.nFileSizeLow;
	sizeConverter.High = info.nFileSizeHigh;
	WLocalNode	*__root = new WLocalNode(path, sizeConverter.ull, NULL, this, WLocalNode::FILE);

	this->basePath = lpath->path.substr(0, lpath->path.rfind('\\'));
    __root->setBasePath(this->basePath.c_str());
    this->_root = __root;
  }
  this->registerTree(this->parent, this->_root);
  return ;
}

int local::vopen(Node *node)
{
  if (node != NULL) {
	std::string	filePath = this->basePath + "/" + node->absolute();
	
    return ((int)CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
			     0, OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL, 0));
  }
  else
    return -1;
}

int local::vread(int fd, void *buff, unsigned int size)
{
  DWORD readed;
  
  if (ReadFile((HANDLE)fd, buff, size,  &readed ,0))
    return (readed);
  else
    return (0);
}

int local::vclose(int fd)
{
  return (!CloseHandle((HANDLE)fd));
}

uint64_t	local::vseek(int fd, uint64_t offset, int whence)
{
  PLONG		highSeek = NULL;
  uint32_t	lowSeek;
  
  // SetFilePointer takes two signed (!) 32bits value to form a 64bit value to seek to
  // First is the direct, second is a pointer to this value (NULL if 32bit is enought).
  if (offset > 0xffffffff) {
	lowSeek = offset & 0x00000000ffffffff;
	*highSeek = (offset & 0xffffffff00000000) >> 32;
  }
  else
	lowSeek = (uint32_t)offset;
  if (whence == 0)
    whence = FILE_BEGIN;
  else if (whence == 1)
    whence = FILE_CURRENT;
  else if (whence == 2)
    whence = FILE_END;
  return (SetFilePointer((HANDLE)fd, lowSeek, highSeek, whence)); 
}

uint64_t	local::vtell(int32_t fd)
{
  uint64_t	pos;

  pos = this->vseek(fd, 0, 1);
  return pos;
}

unsigned int local::status(void)
{
//status called

  return (nfd);
}

//XXX


//extern "C" 
//{
//  fso* create(void)
//  {
//    return (new local(string("local")));
//  }
//    
//  void destroy(fso *p)
//  {
//    delete p;
//  }
//
//  class proxy 
//  {
//    public :
//    proxy()
//    {
//     CModule* mod = new CModule("local", create);
//     mod->conf->add("path", "path");
//     mod->conf->add("parent", "node");
//     mod->conf->add_const("mime-type", std::string("data"));
//	 mod->tags = "fs";
//    }
//  };
//  proxy p;
//}
