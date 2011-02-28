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

local::local(): fso("local")
{
}

local::~local()
{
}

void						local::start(std::map<std::string, Variant* > args)
{
  std::map<std::string, Variant* >::iterator	argit;
 
  
  if ((argit = args.find("parent")) != args.end())
    this->parent = argit->second->value<Node*>();
  else
    this->parent = VFS::Get().GetNode("/");
  if ((argit = args.find("path")) != args.end())
    if (argit->second == NULL)
      throw(envError("local module requires at least one path parameter"));
  else
    throw(envError("local module requires path argument"));

  std::list<Variant *>				paths = argit->second->value<std::list<Variant* > >();
  std::list<Variant* >::iterator	path = paths.begin();
  for  (; path != paths.end(); path++)
  {
	  this->createPath(((*path)->value<Path*>())->path);
  }

}

std::string local::relativePath(std::string path)
{
  std::string relPath;

  while (path.find('/') != std::string::npos) {
	path[path.find('/')] = '\\';
  }
  if ((path.rfind('/') + 1) == path.length())
    path.resize(path.rfind('/'));
  if ((path.rfind('\\') + 1) == path.length())
    path.resize(path.rfind('\\'));
  relPath = path;
  if (relPath.rfind("\\") <= relPath.size())
    relPath = relPath.substr(relPath.rfind("\\") + 1);
  else 
	relPath = relPath.substr(relPath.rfind("/") + 1);

  return relPath;
}

void	local::createPath(std::string origPath)
{
  WIN32_FILE_ATTRIBUTE_DATA	info;
  s_ull						sizeConverter;

  cout << "createPath( " << origPath << " )" << endl;
  std::string relPath = this->relativePath(origPath);
  cout << "createPath relPath " << relPath << endl;

  if(!GetFileAttributesExA(origPath.c_str(), GetFileExInfoStandard, &info))
  {
//    res->add_const("error", string("error stating file:" + relPath)); 
	  res["error"] = new Variant(std::string("error stating file: " + relPath));
    return ;
  }
  if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
  {
	  cout << "create directory not yet implemented" << endl;
	  /*
    // Create a virtual directory
    this->__root = new WLocalNode(relPath, 0, NULL, this, WLocalNode::DIR);	
    this->basePath = origPath.substr(0, origPath.rfind('\\'));
    this->__root->setBasePath(this->basePath.c_str());
    //recurse
    this->frec(origPath.c_str(), this->__root);*/
  }
  else 
  {
	cout << "create a virtual file" << endl;
	// Create a virtual file
    sizeConverter.Low = info.nFileSizeLow;
    sizeConverter.High = info.nFileSizeHigh;
    this->__root = new WLocalNode(origPath, sizeConverter.ull, NULL, this, WLocalNode::FILE);
    this->basePath = origPath.substr(0, origPath.rfind('\\'));
	cout << "seting base path" << this->basePath << endl;
    this->__root->setBasePath(this->basePath.c_str());
  }
  this->registerTree(this->parent, this->__root);
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
  s_ull				sizeConverter;
  sizeConverter.ull = offset;	
  
  if (whence == 0)
    whence = FILE_BEGIN;
  else if (whence == 1)
    whence = FILE_CURRENT;
  else if (whence == 2)
    whence = FILE_END; 
  return (SetFilePointer((HANDLE)fd, sizeConverter.Low, ((long*)&sizeConverter.High), whence)); 
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

