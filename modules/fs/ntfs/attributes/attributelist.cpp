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

#include "attributelist.hpp"

AttributeAttributeList::AttributeAttributeList(VFile *vFile, Attribute &parent)
{
  _attributeHeader = new AttributeHeader(*(parent.attributeHeader()));

  _readBuffer = parent.readBuffer();
  _attributeOffset = parent.attributeOffset();
  _bufferOffset = parent.bufferOffset();
  _offsetInRun = 0;
  _offsetRunIndex = 0;
  _currentEntry = 0;
  _vfile = vFile;
  _clusterSize = parent.clusterSize();

  if (_attributeHeader->nonResidentFlag) {
    setRunList();
    _attributeNonResidentDataHeader = new AttributeNonResidentDataHeader(*(parent.nonResidentDataHeader()));
    size(_attributeNonResidentDataHeader->attributeContentActualSize);

    _contentBuffer = new uint8_t[_size];
    uint64_t	readOffset;
    uint64_t	readPos = 0;
    uint64_t	readSize = _size;

    while ((readOffset = nextOffset())) {
      _vfile->seek(readOffset);
      if (readSize > _clusterSize) {
	_vfile->read(_contentBuffer + readPos, _clusterSize);
	readPos += _clusterSize;
	readSize -= _clusterSize;
      }
      else {
	_vfile->read(_contentBuffer + readPos, readSize);
	readPos += readSize;
	readSize = 0;
      }
    }
    _dataOffset = 0;
  }
  else {
    uint8_t	i;
    _attributeResidentDataHeader = new AttributeResidentDataHeader(*(parent.residentDataHeader()));
    size(_attributeResidentDataHeader->contentSize);
    offset(_attributeResidentDataHeader->contentOffset);
    _fixupIndexesSize = parent.fixupIndexesSize();
    _fixupIndexes = new uint64_t[_fixupIndexesSize];
    for (i = 0; i < _fixupIndexesSize; i++) {
      _fixupIndexes[i] = parent.fixupIndexes()[i];
    }

    _dataOffset = _attributeResidentDataHeader->contentOffset;
  }
  //  content();
}

AttributeAttributeList::~AttributeAttributeList()
{
  ;
}

void		AttributeAttributeList::content()
{
  uint16_t	contentSize;

  if (_attributeHeader->nonResidentFlag) {
    ;
  }
  else {
    contentSize = _attributeResidentDataHeader->contentSize;
  }
  while (_dataOffset < contentSize) {
    if (_attributeHeader->nonResidentFlag) {
      ;
    }
    else {
      DEBUG(INFO, "attribute content ? offset 0x%x size 0x%x\n", _dataOffset + _bufferOffset, _attributeResidentDataHeader->contentSize);
      _data = (AttributeAttributeList_t *)(_readBuffer + _bufferOffset + _dataOffset);
    }

    DEBUG(INFO, "\t\tAttribute type 0x%x: %s\n", _data->attributeType, getName(_data->attributeType).c_str());
    DEBUG(INFO, "\t\tEntry length 0x%x\n", _data->entryLength);
    DEBUG(INFO, "\t\tLength of name 0x%x\n", _data->nameLength);
    DEBUG(INFO, "\t\tOffset to name 0x%x\n", _data->nameOffset);
#if __WORDSIZE == 64
    DEBUG(INFO, "\t\tStarting VCN in attribute 0x%lx\n", _data->startingVCNInAttribute);
    DEBUG(INFO, "\t\tFile reference where attribute is located 0x%lx\n", _data->fileReference);
    DEBUG(INFO, "\t\tMftEntry reference %lu (0x%lx)\n", _data->fileReference & 0xffffffUL, _data->fileReference & 0xffffffUL);
#else
    DEBUG(INFO, "\t\tStarting VCN in attribute 0x%llx\n", _data->startingVCNInAttribute);
    DEBUG(INFO, "\t\tFile reference where attribute is located 0x%llx\n", _data->fileReference);
    DEBUG(INFO, "\t\tMftEntry reference %llu (0x%llx)\n", _data->fileReference & 0xffffffULL, _data->fileReference & 0xffffffULL);
#endif
    DEBUG(INFO, "\t\tAttribute ID 0x%x\n\n", _data->attributeID);
    _dataOffset += _data->entryLength;
  }
}

uint32_t	AttributeAttributeList::getExternalAttributeIndexRoot()
{
  uint16_t	contentSize;

  if (_attributeHeader->nonResidentFlag) {
    ;
  }
  else {
    contentSize = _attributeResidentDataHeader->contentSize;
  }
  while (_dataOffset < contentSize) {
    if (_attributeHeader->nonResidentFlag) {
      ;
    }
    else {
      _data = (AttributeAttributeList_t *)(_readBuffer + _bufferOffset + _dataOffset);
    }
    if (_data->attributeType == ATTRIBUTE_INDEX_ROOT) {
#if __WORDSIZE == 64
      return _data->fileReference & 0xffffffUL;
#else
      return _data->fileReference & 0xffffffULL;
#endif
    }
    _dataOffset += _data->entryLength;
  }
  return 0;
}

uint32_t	AttributeAttributeList::getExternalAttributeIndexAlloc()
{
  uint16_t	contentSize;

  if (_attributeHeader->nonResidentFlag) {
    ;
  }
  else {
    contentSize = _attributeResidentDataHeader->contentSize;
  }
  while (_dataOffset < contentSize) {
    if (_attributeHeader->nonResidentFlag) {
      ;
    }
    else {
      _data = (AttributeAttributeList_t *)(_readBuffer + _bufferOffset + _dataOffset);
    }
    if (_data->attributeType == ATTRIBUTE_INDEX_ALLOCATION) {
#if __WORDSIZE == 64
      return _data->fileReference & 0xffffffUL;
#else
      return _data->fileReference & 0xffffffULL;
#endif
    }
    _dataOffset += _data->entryLength;
  }
  return 0;
}

uint32_t	AttributeAttributeList::getExternalAttributeFileName()
{
  uint32_t	mftEntry;
  uint16_t	contentSize;

  if (_attributeHeader->nonResidentFlag) {
    contentSize = _size;
  }
  else {
    contentSize = _attributeResidentDataHeader->contentSize;
  }
  while (_dataOffset < contentSize) {
    if (_attributeHeader->nonResidentFlag) {
      _data = (AttributeAttributeList_t *)(_contentBuffer + _dataOffset);
    }
    else {
      _data = (AttributeAttributeList_t *)(_readBuffer + _bufferOffset + _dataOffset);
    }
    if (_data->attributeType == ATTRIBUTE_FILE_NAME) {
#if __WORDSIZE == 64
      mftEntry = _data->fileReference & 0xffffffUL;
#else
      mftEntry = _data->fileReference & 0xffffffULL;
#endif
      if (mftEntry != _currentEntry && mftEntry != _id) {
	_currentEntry = mftEntry;
	return mftEntry;
      }
    }
    if (!_data->entryLength) {
      return 0;
    }
    _dataOffset += _data->entryLength;
  }
  return 0;
}

uint32_t	AttributeAttributeList::getExternalAttributeData()
{
  uint16_t	contentSize;

  if (_attributeHeader->nonResidentFlag) {
    ;
  }
  else {
    contentSize = _attributeResidentDataHeader->contentSize;
  }
  while (_dataOffset < contentSize) {
    if (_attributeHeader->nonResidentFlag) {
      ;
    }
    else {
      _data = (AttributeAttributeList_t *)(_readBuffer + _bufferOffset + _dataOffset);
    }
    if (_data->attributeType == ATTRIBUTE_DATA) {
#if __WORDSIZE == 64
      return _data->fileReference & 0xffffffUL;
#else
      return _data->fileReference & 0xffffffULL;
#endif
    }
    _dataOffset += _data->entryLength;
  }
  return 0;
}