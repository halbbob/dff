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

#include "standardinformation.hpp"

AttributeStandardInformation::AttributeStandardInformation(Attribute &parent)
{
  _attributeHeader = new AttributeHeader(*(parent.attributeHeader()));
  _attributeResidentDataHeader = new AttributeResidentDataHeader(*(parent.residentDataHeader()));

  _readBuffer = parent.readBuffer();
  _attributeOffset = parent.attributeOffset();
  _bufferOffset = parent.bufferOffset();
  _offsetInRun = 0;
  _offsetRunIndex = 0;

  _data = new AttributeStandardInformation_t(*((AttributeStandardInformation_t *)
					       (_readBuffer + _bufferOffset +
						_attributeResidentDataHeader->contentOffset)));

  //  content();
}

AttributeStandardInformation::~AttributeStandardInformation()
{
  ;
}

void		AttributeStandardInformation::content()
{
  struct tm	*date;
  std::string	dateString;

  //  _data = (AttributeStandardInformation_t *)(_readBuffer + _bufferOffset +
  //					   _attributeResidentDataHeader->contentOffset);

  setDateToString(_data->creationTime, &date, &dateString, true);
#if __WORDSIZE == 64
  DEBUG(CRITICAL, "\t\t\tSI Creation time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->creationTime);
#else
  DEBUG(CRITICAL, "\t\t\tSI Creation time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->creationTime);
#endif
  setDateToString(_data->fileAlteredTime, &date, &dateString, true);
#if __WORDSIZE == 64
  DEBUG(CRITICAL, "\t\t\tSI File altered time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->fileAlteredTime);
#else
  DEBUG(CRITICAL, "\t\t\tSI File altered time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->fileAlteredTime);
#endif
  setDateToString(_data->mftAlteredTime, &date, &dateString, true);
#if __WORDSIZE == 64
  DEBUG(CRITICAL, "\t\t\tSI MFT altered time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->mftAlteredTime);
#else
  DEBUG(CRITICAL, "\t\t\tSI MFT altered time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->mftAlteredTime);
#endif
  setDateToString(_data->fileAccessedTime, &date, &dateString, true);
#if __WORDSIZE == 64
  DEBUG(CRITICAL, "\t\t\tSI File accessed time:\t%s\t(0x%.16lx)\n", dateString.c_str(), _data->fileAccessedTime);
#else
  DEBUG(CRITICAL, "\t\t\tSI File accessed time:\t%s\t(0x%.16llx)\n", dateString.c_str(), _data->fileAccessedTime);
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
    DEBUG(CRITICAL, "\t\t\tunknown\n");
    ;
  }
  if (_data->maxNumberOfVersions) {
    DEBUG(CRITICAL, "\t\t\tMaximum number of versions 0x%x\n", _data->maxNumberOfVersions);
    ;
  }
  else {
    DEBUG(CRITICAL, "\t\t\tMaximum number of versions not used\n");
    ;
  }
  if (_data->versionNumber) {
    DEBUG(CRITICAL, "\t\t\tVersion number 0x%x\n", _data->versionNumber);
    ;
  }
  else {
    DEBUG(CRITICAL, "\t\t\tVersion number not used\n");
    DEBUG(CRITICAL, "\t\t\tClass ID 0x%x\n", _data->classID);
    DEBUG(CRITICAL, "\t\t\tOwner ID 0x%x\n", _data->ownerID);
    DEBUG(CRITICAL, "\t\t\tSecurity ID 0x%x\n", _data->securityID);
    DEBUG(CRITICAL, "\t\t\tQuota charged 0x%x\n", _data->quotaCharged);
#if __WORDSIZE == 64
    DEBUG(CRITICAL, "\t\t\tUpdate sequence number (USN) 0x%lx\n", _data->updateSequenceNumber);
#else
    DEBUG(CRITICAL, "\t\t\tUpdate sequence number (USN) 0x%llx\n", _data->updateSequenceNumber);
#endif
    ;
  }
}

