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

#include "ntfsnode.hpp"

#include <sstream>

NtfsNode::NtfsNode(std::string Name, uint64_t size, Node *parent,
		   fso *fsobj, bool isFile, AttributeFileName *metaFileName,
		   AttributeStandardInformation *metaStandardInformation,
		   MftEntry *mft):
  Node(Name, size, parent, fsobj)
{
  _metaFileName = metaFileName;
  if (metaStandardInformation) {
    _SI = new AttributeStandardInformation(*metaStandardInformation);
  }
  else {
    _SI = NULL;
  }
  _isFile = isFile;
  if (isFile) {
    this->setFile();
    setSize(size);
  }
  else {
    this->setDir();
  }
  _mftEntry = 0;
  _physOffset = 0;
  _mft = mft;
  setSize(size);
}

NtfsNode::NtfsNode(std::string Name, uint64_t size, Node *parent,
		   fso *fsobj, bool isFile, AttributeFileName *metaFileName,
		   AttributeStandardInformation *metaStandardInformation,
		   MftEntry *mft, uint32_t mftEntry, uint64_t offset):
  Node(Name, size, parent, fsobj)
{
  _metaFileName = metaFileName;
  if (metaStandardInformation) {
    _SI = new AttributeStandardInformation(*metaStandardInformation);
  }
  else {
    _SI = NULL;
  }
  _isFile = isFile;
#if __WORDSIZE == 64
  DEBUG(INFO, "%s %lu\n", Name.c_str(), size);
#else
  DEBUG(INFO, "%s %llu\n", Name.c_str(), size);
#endif
  if (isFile) {
    this->setFile();
    setSize(size);
  }
  else
    this->setDir();
  _mftEntry = mftEntry;
  _physOffset = offset;
  _mft = mft;
}

NtfsNode::~NtfsNode()
{
  ;
}

std::map<std::string, class Variant *>	NtfsNode::_headerToAttribute(Attribute *attr)
{
  std::map<std::string, class Variant *>	headerMap;
  std::ostringstream				stringBuff;
  bool						flagsInserted;

  headerMap.insert(_dataToAttr("Length", attr->attributeHeader()->attributeLength));
  headerMap.insert(_dataToAttr("Is non-resident", attr->attributeHeader()->nonResidentFlag));
  headerMap.insert(_dataToAttr("Name length", attr->attributeHeader()->nameLength));
  headerMap.insert(_dataToAttr("Attribute number", attr->attributeHeader()->attributeIdentifier));
  stringBuff << attr->attributeHeader()->flags << " (0x" << hex << attr->attributeHeader()->flags << "): ";
  if (attr->attributeHeader()->flags & ATTRIBUTE_FLAG_COMPRESSED) { stringBuff << "Compressed"; flagsInserted = true; }
  if (attr->attributeHeader()->flags & ATTRIBUTE_FLAG_ENCRYPTED) { stringBuff << (flagsInserted ? ", " : "") << "Encrypted"; flagsInserted = true; }
  if (attr->attributeHeader()->flags & ATTRIBUTE_FLAG_SPARSE) { stringBuff << (flagsInserted ? ", " : "") << "Sparse"; flagsInserted = true; }
  
  if (attr->attributeHeader()->nonResidentFlag) {
    headerMap.insert(_dataToAttr("Starting VCN", attr->nonResidentDataHeader()->startingVCN));
    headerMap.insert(_dataToAttr("Ending VCN", attr->nonResidentDataHeader()->endingVCN));
    headerMap.insert(_dataToAttr("Run-list offset", attr->nonResidentDataHeader()->runListOffset));
    headerMap.insert(_dataToAttr("Compression unit size", attr->nonResidentDataHeader()->compressionUnitSize));
    headerMap.insert(_dataToAttr("Content allocated size", attr->nonResidentDataHeader()->attributeContentAllocatedSize));
    headerMap.insert(_dataToAttr("Content actual size", attr->nonResidentDataHeader()->attributeContentActualSize));
    headerMap.insert(_dataToAttr("Content initialized size", attr->nonResidentDataHeader()->attributeContentInitializedSize));
  }
  else {
    headerMap.insert(_dataToAttr("Content size", attr->residentDataHeader()->contentSize));
    headerMap.insert(_dataToAttr("Content offset", attr->residentDataHeader()->contentOffset));
  }

  return headerMap;
}

void						NtfsNode::extendedAttributes(Attributes	*attr)
{
  DEBUG(INFO, "in extended attributes\n");
  if (_isFile)
    attr->push("size", new Variant(size()));

  if (!_SI) {
    return ;
  }

  attr->push("MFT entry number", _dataToAttr(_mftEntry));
  attr->push("MFT physical offset", _dataToAttr(_physOffset));

  Attribute	*attribute;

  /*
  mftData->clusterSize(4096);
  mftData->indexRecordSize(4096);
  mftData->sectorSize(512);
  mftData->mftEntrySize(1024);
  */
  if (!_mft->decode(_physOffset)) {
    return ;
  }

  //  _mft->readHeader();
  while ((attribute = _mft->getNextAttribute())) {
    std::map<std::string, class Variant *>	attributeMap;
    std::string					attributeFullName;
    std::map<std::string, class Variant *>	attributeHeaderMap;
    
    attribute->readHeader();
    attributeFullName = attribute->getFullName();
    attributeHeaderMap = _headerToAttribute(attribute);

    if (attribute->getType() == ATTRIBUTE_STANDARD_INFORMATION) {
      _standardInformation(&attributeMap, new AttributeStandardInformation(*attribute));
    }
    DEBUG(INFO, "got name: %s\n", attributeFullName.c_str());
    attributeMap.insert(std::pair<std::string, class Variant *>("Header", new Variant(attributeHeaderMap)));
    attr->push(attributeFullName, new Variant(attributeMap));
  }
}

void	NtfsNode::_standardInformation(std::map<std::string, class Variant *> *map, AttributeStandardInformation *nAttr)
{
  //  std::map<std::string, class Variant *>	SImap = *map;
  std::map<std::string, class Variant *>	HeaderMap;
  std::map<std::string, class Variant *>	flagsMap;
  std::ostringstream				stringBuff;
  bool						flagsInserted = false;

  flagsInserted = false;
  stringBuff.str("");
  stringBuff << nAttr->data()->flags << " (0x" << hex << nAttr->data()->flags << "): ";
  if (nAttr->data()->flags & ATTRIBUTE_SI_FLAG_READ_ONLY) { stringBuff << "Read only"; flagsInserted = true; }
  if (nAttr->data()->flags & ATTRIBUTE_SI_FLAG_HIDDEN) { stringBuff << (flagsInserted ? ", " : "") << "Hidden"; flagsInserted = true; }
  if (nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SYSTEM) { stringBuff << (flagsInserted ? ", " : "") << "System"; flagsInserted = true; }
  if (nAttr->data()->flags & ATTRIBUTE_SI_FLAG_ARCHIVE) { stringBuff << (flagsInserted ? ", " : "") << "Archive"; flagsInserted = true; }
  if (nAttr->data()->flags & ATTRIBUTE_SI_FLAG_DEVICE) { stringBuff << (flagsInserted ? ", " : "") << "Device"; flagsInserted = true; }
  if (nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SHARPNORMAL) { stringBuff << (flagsInserted ? ", " : "") << "#Normal"; flagsInserted = true; }
  if (nAttr->data()->flags & ATTRIBUTE_SI_FLAG_TEMPORARY) { stringBuff << (flagsInserted ? ", " : "") << "Temporary"; flagsInserted = true; }
  if (nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SPARSE_FILE) { stringBuff << (flagsInserted ? ", " : "") << "Sparse"; flagsInserted = true; }
  if (nAttr->data()->flags & ATTRIBUTE_SI_FLAG_REPARSE_POINT) { stringBuff << (flagsInserted ? ", " : "") << "Reparse point"; flagsInserted = true; }
  if (nAttr->data()->flags & ATTRIBUTE_SI_FLAG_COMPRESSED) { stringBuff << (flagsInserted ? ", " : "") << "Compressed"; flagsInserted = true; }
  if (nAttr->data()->flags & ATTRIBUTE_SI_FLAG_OFFLINE) { stringBuff << (flagsInserted ? ", " : "") << "Offline"; flagsInserted = true; }
  if (nAttr->data()->flags & ATTRIBUTE_SI_FLAG_CONTENT_NOT_INDEXED) { stringBuff << (flagsInserted ? ", " : "") << "Content is not being indexed for faster searches"; flagsInserted = true; }
  if (nAttr->data()->flags & ATTRIBUTE_SI_FLAG_ENCRYPTED) { stringBuff << (flagsInserted ? ", " : "") << "Encrypted"; flagsInserted = true; }
  if (!(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_READ_ONLY) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_HIDDEN) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SYSTEM) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_ARCHIVE) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_DEVICE) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SHARPNORMAL) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_TEMPORARY) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SPARSE_FILE) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_REPARSE_POINT) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_COMPRESSED) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_OFFLINE) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_CONTENT_NOT_INDEXED) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_ENCRYPTED)) { stringBuff << (flagsInserted ? ", " : "") << "unknown"; }

  map->insert(_dataToVTime("Creation time", nAttr->data()->creationTime));
  map->insert(_dataToVTime("File altered time", nAttr->data()->fileAlteredTime));
  map->insert(_dataToVTime("MFT altered time", nAttr->data()->mftAlteredTime));
  map->insert(_dataToVTime("File accessed time", nAttr->data()->fileAccessedTime));
  map->insert(std::pair<std::string, class Variant *>("Flags", new Variant(stringBuff.str())));
  map->insert(_dataToAttr("Max number of versions", nAttr->data()->maxNumberOfVersions));
  map->insert(_dataToAttr("Version number", nAttr->data()->versionNumber));
  map->insert(_dataToAttr("Class ID", nAttr->data()->classID));
  map->insert(_dataToAttr("Owner ID", nAttr->data()->ownerID));
  map->insert(_dataToAttr("Security ID", nAttr->data()->securityID));
  map->insert(_dataToAttr("Quota charged", nAttr->data()->quotaCharged));
  map->insert(_dataToAttr("Update sequence number", nAttr->data()->updateSequenceNumber));
}

std::pair<std::string, class Variant *>	NtfsNode::_dataToAttr(std::string key, uint32_t value)
{
  std::ostringstream	stringBuff;
  stringBuff << value << " (0x" << hex << value << ")";
  return std::pair<std::string, class Variant *>(key, new Variant(stringBuff.str()));
}

Variant	*NtfsNode::_dataToAttr(uint32_t value)
{
  std::ostringstream	stringBuff;
  stringBuff << value << " (0x" << hex << value << ")";
  return new Variant(stringBuff.str());
}

std::pair<std::string, class Variant *>	NtfsNode::_dataToAttr(std::string key, uint64_t value)
{
  std::ostringstream	stringBuff;
  stringBuff << value << " (0x" << hex << value << ")";
  return std::pair<std::string, class Variant *>(key, new Variant(stringBuff.str()));
}

Variant	*NtfsNode::_dataToAttr(uint64_t value)
{
  std::ostringstream	stringBuff;
  stringBuff << value << " (0x" << hex << value << ")";
  return new Variant(stringBuff.str());
}

std::pair<std::string, class Variant *>	NtfsNode::_dataToVTime(std::string key, uint64_t value)
{
  vtime	*vt = new vtime();

  _SI->setDateToVTime(value, vt);
  return std::pair<std::string, class Variant *>(key, new Variant(vt));
}

std::pair<std::string, class Variant *>	NtfsNode::_dataToAttr(std::string key, uint16_t value)
{
  std::ostringstream	stringBuff;
  stringBuff << value << " (0x" << hex << value << ")";
  return std::pair<std::string, class Variant *>(key, new Variant(stringBuff.str()));
}

std::pair<std::string, class Variant *>	NtfsNode::_dataToAttr(std::string key, uint8_t value)
{
  return _dataToAttr(key, (uint16_t)value);
}

void	NtfsNode::fileMapping(FileMapping *fm)
{
  if (_isFile && size()) {
    //    FileMapping	*fm = new FileMapping();

    if (_data->attributeHeader()->nonResidentFlag) {
      DEBUG(INFO, "NtfsNode::fileMapping nonResident\n");
      _offsetFromRunList(fm);
    }
    else {
      DEBUG(INFO, "NtfsNode::fileMapping resident\n");
      _offsetResident(fm);
    }
    //    return fm;
  }
  //  return NULL;
}

/**
 * Set data chunks for data inside of MFT attribute
 *  Fixups values are present in the last two bytes of secto
 *
 *  TODO if mftEntrySize > sectorSize * 2 ; we need to loop to replace fixup
 */
void	NtfsNode::_offsetResident(FileMapping *fm)
{
  uint16_t	dataStart = _data->residentDataHeader()->contentOffset +
    _data->getAttributeOffset();
  uint16_t	firstChunkSize = _data->getSectorSize() - SIZE_2BYTES -
    dataStart;
  uint16_t	remainSize = size() - firstChunkSize - SIZE_2BYTES;

  DEBUG(INFO, "\tdataStart: 0x%x\n", dataStart);
  DEBUG(INFO, "\tsectorSize - 2: 0x%x\n", _data->getSectorSize() - 2);
  
  fm->push(0, firstChunkSize, _node, _data->getOffset());
  fm->push(firstChunkSize, SIZE_2BYTES, _node, _data->getFixupOffset(0));
  fm->push(firstChunkSize + SIZE_2BYTES, remainSize, _node, SIZE_2BYTES +
	   firstChunkSize + _data->getOffset());

}

/**
 * Set data chunks for data outside of MFT attribute, offsets are in a runlist
 */
void		NtfsNode::_offsetFromRunList(FileMapping *fm)
{
  uint16_t	currentRunIndex = 0;
  uint64_t	currentOffset = 0;
  uint64_t	registeredClusters = 0;
  uint64_t	newSize;

  OffsetRun	*run;

  DEBUG(INFO, "Offset list size: %u\n",_data->getOffsetListSize());
  while ((currentRunIndex < _data->getOffsetListSize())) {
    run = _data->getOffsetRun(currentRunIndex);

    newSize = (run->runLength - registeredClusters) * _data->clusterSize();

#if __WORDSIZE == 64
    DEBUG(INFO, " (0x%x - 0x%lx) * 0x%x\n", run->runLength, newSize, _data->clusterSize());
    DEBUG(INFO, " cO: 0x%lx si: 0x%lx\n", currentOffset, (run->runLength - newSize) * _data->clusterSize());
    DEBUG(INFO, "offset: 0x%lx\n", run->runOffset);
#else
    DEBUG(INFO, " (0x%x - 0x%llx) * 0x%x\n", run->runLength, newSize, _data->clusterSize());
    DEBUG(INFO, " cO: 0x%llx si: 0x%llx\n", currentOffset, (run->runLength - newSize) * _data->clusterSize());
    DEBUG(INFO, "offset: 0x%llx\n", run->runOffset);
#endif

    if (run->runOffset) {
      if (currentOffset + newSize > _data->getSize()) {
#if __WORDSIZE == 64
	DEBUG(INFO, "current1: 0x%lx, initsize: 0x%lx\n", currentOffset, _data->getInitSize());
#else
	DEBUG(INFO, "current1: 0x%llx, initsize: 0x%llx\n", currentOffset, _data->getInitSize());
#endif
	// XXX if > initSize, need to create shadow node
	fm->push(currentOffset, newSize - (currentOffset + newSize - _data->getSize()),
		 _node, run->runOffset * _data->clusterSize());
#if __WORDSIZE == 64
	DEBUG(INFO, "node pushed size 0x%lx from 0x%lx\n", newSize - (currentOffset + newSize - _data->getSize()),run->runOffset * _data->clusterSize() );
#else
	DEBUG(INFO, "node pushed size 0x%llx from 0x%llx\n", newSize - (currentOffset + newSize - _data->getSize()),run->runOffset * _data->clusterSize() );
#endif
      }
      else {
#if __WORDSIZE == 64
	DEBUG(INFO, "current2: 0x%lx, initsize: 0x%lx\n", currentOffset, _data->getInitSize());
#else
	DEBUG(INFO, "current2: 0x%llx, initsize: 0x%llx\n", currentOffset, _data->getInitSize());
#endif
	if ((currentOffset + newSize) > _data->getInitSize()) {
	  // > initSize, need to create shadow node
	  fm->push(currentOffset, _data->getInitSize() - currentOffset,
		   _node, run->runOffset * _data->clusterSize());
	  fm->push(currentOffset + (_data->getInitSize() - currentOffset),
		   newSize - (_data->getInitSize() - currentOffset), NULL, 0);
	}
	else {
	  fm->push(currentOffset, newSize, _node, run->runOffset * _data->clusterSize());
	}
      }
    }
    else { // shadow
      fm->push(currentOffset, newSize, NULL, 0);
    }

    currentOffset += (run->runLength - registeredClusters) * _data->clusterSize();
    registeredClusters = run->runLength;

    currentRunIndex++;
  }
  DEBUG(INFO, "\n");
}


void	NtfsNode::modifiedTime(vtime *vt)
{
  if (_SI) {
    _SI->setDateToVTime(_SI->data()->fileAlteredTime, vt);
  }
}

void	NtfsNode::accessedTime(vtime *vt)
{
  if (_SI) {
    _SI->setDateToVTime(_SI->data()->fileAccessedTime, vt);
  }
}

void	NtfsNode::changedTime(vtime *vt)
{
  if (_SI) {
    _SI->setDateToVTime(_SI->data()->creationTime, vt);
  }
}
