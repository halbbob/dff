/* 
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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

#include "data.hpp"

AttributeData::AttributeData()
{
  size(0);
  offset(0);
}

AttributeData::AttributeData(Attribute &parent)
{
  _fixupIndexes = NULL;
  _offsetList = NULL;
  _attributeHeader = new AttributeHeader(*(parent.attributeHeader()));
  _readBuffer = parent.readBuffer();
  _baseOffset = 0;
  _attributeOffset = parent.attributeOffset();
  _bufferOffset = parent.bufferOffset();
  _offsetInRun = 0;
  _offsetRunIndex = 0;
  _offsetListSize = 0;
  _mftIndex = 0;

  _mftEntrySize = parent.mftEntrySize();
  _indexRecordSize = parent.indexRecordSize();
  _sectorSize = parent.sectorSize();
  _clusterSize = parent.clusterSize();
  _currentRunIndex = 0;

  if (_attributeHeader->nonResidentFlag) {
    setRunList();

    _attributeNonResidentDataHeader = new AttributeNonResidentDataHeader(*(parent.nonResidentDataHeader()));
    size(_attributeNonResidentDataHeader->attributeContentActualSize);
    _attributeResidentDataHeader = NULL;
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
    _attributeNonResidentDataHeader = NULL;
  }
    
  DEBUG(INFO, "Data copy ok !!!!\n");
}

AttributeData::~AttributeData()
{
  //  if (_fixupIndexes != NULL) {
  //    delete _fixupIndexes;
  //  }
  if (_attributeNonResidentDataHeader != NULL) {
    delete _attributeNonResidentDataHeader;
  }
  if (_attributeResidentDataHeader != NULL) {
    delete _attributeResidentDataHeader;
  }
  delete _attributeHeader;
}

void	AttributeData::content()
{
  DEBUG(INFO, "In data content !!\n");

}
