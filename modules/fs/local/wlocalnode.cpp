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
 *  Christophe Malinge <cma@digital-forensic.org>
 */

#include "wlocalnode.hpp"
#include <windows.h>

WLocalNode::WLocalNode(std::string Name, uint64_t size, Node* parent, mfso* fsobj, uint8_t type): Node(Name, size, parent, fsobj)
{
  switch (type)
    {
    case DIR:
      this->setDir();
      break;
    case FILE:
      this->setFile();
      break;
    default:
      break;
    }
}

WLocalNode::~WLocalNode()
{
}

/**
 * Set the physical (real) path on the filesystem on the node
 */
void	WLocalNode::setBasePath(std::string *bp)
{
  this->basePath = bp;
}

void				WLocalNode::wtimeToVtime(FILETIME *tt, vtime *vt)
{
	LPSYSTEMTIME	stUTC;

	if (tt == NULL)
		return ;
		
	if (FileTimeToSystemTime(tt, stUTC) == 0)
		return ;
	
	// convert modification time to local time.
	/*
	FileTimeToSystemTime(&ftWrite, &stUTC);
	SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
	*/
	
  	vt->year = stUTC->wYear;
	vt->month = stUTC->wMonth;
	vt->day = stUTC->wDay;
	vt->hour = stUTC->wHour;
	vt->minute = stUTC->wMinute;
	vt->second = stUTC->wSecond;
	vt->dst = 0;	// FIXME
	vt->wday = stUTC->wDayOfWeek;
	vt->yday = 0;	// FIXME
	vt->usecond = stUTC->wMilliseconds;
}

void							WLocalNode::modifiedTime(vtime* vt)
{
	WIN32_FILE_ATTRIBUTE_DATA	info;
	std::string					fsPath;
	
	fsPath = *(this->basePath) + "/" + this->absolute();
	if(!GetFileAttributesExA(fsPath.c_str(), GetFileExInfoStandard, &info))
		return ;
	this->wtimeToVtime(&(info.ftLastWriteTime), vt);
}

void							WLocalNode::accessedTime(vtime* vt)
{
	WIN32_FILE_ATTRIBUTE_DATA	info;
	std::string					fsPath;
	
	fsPath = *(this->basePath) + "/" + this->absolute();
	if(!GetFileAttributesExA(fsPath.c_str(), GetFileExInfoStandard, &info))
		return ;
	this->wtimeToVtime(&(info.ftLastAccessTime), vt);
}

void							WLocalNode::createdTime(vtime* vt)
{
	WIN32_FILE_ATTRIBUTE_DATA	info;
	std::string					fsPath;
	
	fsPath = *(this->basePath) + "/" + this->absolute();
	if(!GetFileAttributesExA(fsPath.c_str(), GetFileExInfoStandard, &info))
		return ;
	this->wtimeToVtime(&(info.ftCreationTime), vt);
}

void		WLocalNode::extendedAttributes(Attributes* attr)
{
	// TODO
	// In attributes, interresting values are ReadOnly, and ... ? Find other !
}
