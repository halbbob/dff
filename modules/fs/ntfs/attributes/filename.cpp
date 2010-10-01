/* 
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2010 ArxSys
 * 
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
 *  Christophe Malinge <cma@digital-forensic.org>
 *
 */


#include "filename.hpp"

AttributeFileName::AttributeFileName(Attribute &parent)
{
  uint16_t	i = 0;
  uint8_t	*name;

  _attributeHeader = new AttributeHeader(*(parent.attributeHeader()));
  _attributeResidentDataHeader = new AttributeResidentDataHeader(*(parent.residentDataHeader()));

  _readBuffer = parent.readBuffer();
  _attributeOffset = parent.attributeOffset();
  _bufferOffset = parent.bufferOffset();
  _offsetInRun = 0;
  _offsetRunIndex = 0;


  _data = new AttributeFileName_t(*((AttributeFileName_t *)(_readBuffer + _bufferOffset +
							    _attributeResidentDataHeader->contentOffset)));
  
  _filename.str("");

  name = (_readBuffer + _bufferOffset + ATTRIBUTE_FN_SIZE +
	  _attributeResidentDataHeader->contentOffset);

  for (i = 0; i < (_attributeResidentDataHeader->contentSize -
		   ATTRIBUTE_FN_SIZE); i++) {
    if (!(i % 2)) {
      //      if (name[i] >= 0x20 && name[i] <= 0x7e) {
	_filename << name[i];
	//      }
    }
  }

  DEBUG(INFO, "found filename: %s\n", _filename.str().c_str());
  //  content();
}

AttributeFileName::~AttributeFileName()
{
  ;
}

std::string	AttributeFileName::getFileName()
{
  return _filename.str();
}

void	AttributeFileName::content()
{
  struct tm		*date;
  std::string		dateString;
  
#if __WORDSIZE == 64
  DEBUG(CRITICAL, "\t\t\tParent directory fileref 0x%.16lx\n", _data->parentDirectoryFileReference);
  DEBUG(CRITICAL, "\t\t\tReal size of file %ld bytes\n", _data->realSizeOfFile);
#else
  DEBUG(CRITICAL, "\t\t\tParent directory fileref 0x%.16llx\n", _data->parentDirectoryFileReference);
  DEBUG(CRITICAL, "\t\t\tReal size of file %lld bytes\n", _data->realSizeOfFile);
#endif
  DEBUG(CRITICAL, "\t\t\tFilename data: %s\n", _filename.str().c_str());
  setDateToString(_data->fileCreationTime, &date, &dateString, true);
#if __WORDSIZE == 64
  DEBUG(CRITICAL, "\t\t\tFile creation time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->fileCreationTime);
#else
  DEBUG(CRITICAL, "\t\t\tFile creation time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->fileCreationTime);
#endif
  setDateToString(_data->fileModificationTime, &date, &dateString, true);
#if __WORDSIZE == 64
  DEBUG(CRITICAL, "\t\t\tFile modification time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->fileModificationTime);
#else
  DEBUG(CRITICAL, "\t\t\tFile modification time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->fileModificationTime);
#endif
  setDateToString(_data->mftModificationTime, &date, &dateString, true);
#if __WORDSIZE == 64
  DEBUG(CRITICAL, "\t\t\tMFT modification time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->mftModificationTime);
#else
  DEBUG(CRITICAL, "\t\t\tMFT modification time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->mftModificationTime);
#endif
  setDateToString(_data->fileAccessTime, &date, &dateString, true);
#if __WORDSIZE == 64
  DEBUG(CRITICAL, "\t\t\tFile access time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->fileAccessTime);
#else
  DEBUG(CRITICAL, "\t\t\tFile access time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->fileAccessTime);
#endif
  DEBUG(CRITICAL, "\t\t\tFlags 0x%x\n", _data->flags);
  if (_data->flags & ATTRIBUTE_SI_FLAG_READ_ONLY) {
    DEBUG(CRITICAL, "\t\t\t\tRead only\n");
    ;
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_HIDDEN) {
    DEBUG(CRITICAL, "\t\t\t\tHidden\n");
    ;
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_SYSTEM) {
    DEBUG(CRITICAL, "\t\t\t\tSystem\n");
    ;
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_ARCHIVE) {
    DEBUG(CRITICAL, "\t\t\t\tArchive\n");
    ;
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_DEVICE) {
    DEBUG(CRITICAL, "\t\t\t\tDevice\n");
    ;
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_SHARPNORMAL) {
    DEBUG(CRITICAL, "\t\t\t\t#Normal\n");
    ;
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_TEMPORARY) {
    DEBUG(CRITICAL, "\t\t\t\tTemporary\n");
    ;
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_SPARSE_FILE) {
    DEBUG(CRITICAL, "\t\t\t\tSparse\n");
    ;
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_REPARSE_POINT) {
    DEBUG(CRITICAL, "\t\t\t\tReparse point\n");
    ;
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_COMPRESSED) {
    DEBUG(CRITICAL, "\t\t\t\tCompressed\n");
    ;
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_OFFLINE) {
    DEBUG(CRITICAL, "\t\t\t\tOffline\n");
    ;
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_CONTENT_NOT_INDEXED) {
    DEBUG(CRITICAL, "\t\t\t\tContent is not being indexed for faster searches\n");
    ;
  }
  if (_data->flags & ATTRIBUTE_SI_FLAG_ENCRYPTED) {
    DEBUG(CRITICAL, "\t\t\t\tEncrypted\n");
    ;
  }
  if (!(_data->flags & ATTRIBUTE_SI_FLAG_READ_ONLY)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_HIDDEN)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_SYSTEM)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_ARCHIVE)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_DEVICE)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_SHARPNORMAL)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_TEMPORARY)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_SPARSE_FILE)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_REPARSE_POINT)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_COMPRESSED)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_OFFLINE)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_CONTENT_NOT_INDEXED)
      && !(_data->flags & ATTRIBUTE_SI_FLAG_ENCRYPTED)) {
    DEBUG(CRITICAL, "\t\t\t\tunknown\n");
  }
  DEBUG(CRITICAL, "\t\t\tReparse value 0x%x\n", _data->reparseValue);
  DEBUG(CRITICAL, "\t\t\tName length 0x%x\n", _data->nameLength);
  DEBUG(CRITICAL, "\t\t\tNamespace is 0x%x corresponding to:\n", _data->nameSpace);
  if (_data->nameSpace & ATTRIBUTE_FN_NAMESPACE_POSIX) {
    DEBUG(CRITICAL, "\t\t\t\tPOSIX (name is case sensitive, allows all Unicode chars except '/' and NULL)\n");
    ;
  }
  if (_data->nameSpace & ATTRIBUTE_FN_NAMESPACE_WIN32_AND_DOS) { 
    DEBUG(CRITICAL, "\t\t\t\tWin32 and DOS (original name fits in DOS namespace)\n");
    ;
  }
  if (_data->nameSpace & ATTRIBUTE_FN_NAMESPACE_WIN32) { 
    DEBUG(CRITICAL, "\t\t\t\tWin32 (name is case insensitive, allows most Unicode chars except '/', '\', ':', '>', '<' and '?')\n");
    ;
  }
  if (_data->nameSpace & ATTRIBUTE_FN_NAMESPACE_DOS) { 
    DEBUG(CRITICAL, "\t\t\t\tDOS (name is case insensitive, upper case, no special chars, name length <= 8, extension length <= 3\n");
    ;
  }
}

