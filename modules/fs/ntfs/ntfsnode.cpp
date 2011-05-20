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

#include "ntfsnode.hpp"

#include <sstream>

NtfsNode::NtfsNode(std::string Name, uint64_t size, Node *parent,
		   Ntfs *fsobj, bool isFile, AttributeFileName *metaFileName,
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
		   Ntfs *fsobj, bool isFile, AttributeFileName *metaFileName,
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
  std::map<std::string, class Variant *>	flagsMap;
  std::ostringstream				stringBuff;

  headerMap.insert(_dataToAttr("Length", attr->attributeHeader()->attributeLength));
  headerMap.insert(_dataToAttr("Is non-resident", attr->attributeHeader()->nonResidentFlag));
  headerMap.insert(_dataToAttr("Name length", attr->attributeHeader()->nameLength));
  headerMap.insert(_dataToAttr("Attribute number", attr->attributeHeader()->attributeIdentifier));

  flagsMap.insert(std::pair<std::string, class Variant *>("Value", new Variant(attr->attributeHeader()->flags)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Compressed", new Variant((attr->attributeHeader()->flags & ATTRIBUTE_FLAG_COMPRESSED) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Encrypted", new Variant((attr->attributeHeader()->flags & ATTRIBUTE_FLAG_ENCRYPTED) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Sparse", new Variant((attr->attributeHeader()->flags & ATTRIBUTE_FLAG_SPARSE) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Unknown flag present", new Variant((attr->attributeHeader()->flags && !(attr->attributeHeader()->flags & ATTRIBUTE_FLAG_COMPRESSED) && !(attr->attributeHeader()->flags & ATTRIBUTE_FLAG_ENCRYPTED) && !(attr->attributeHeader()->flags & ATTRIBUTE_FLAG_SPARSE)))));

  headerMap.insert(std::pair<std::string, class Variant *>("Flags", new Variant(flagsMap)));

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


Attributes				NtfsNode::_attributes()
{
  Attributes	attr;

  DEBUG(INFO, "in extended attributes\n");
  //if (ntfsNode->_isFile)
    //attr["size"] = new Variant(ntfsNode->size());

  if (!(this->_SI)) {
    return attr;
  }

  attr["MFT entry number"] = this->_dataToAttr(this->_mftEntry);
  attr["MFT physical offset"] = this->_dataToAttr(this->_physOffset);

  Attribute	*attribute;

  attr["altered"] = new Variant(new vtime(this->_SI->data()->fileAlteredTime, TIME_MS_64));
  attr["accessed"] = new Variant(new vtime(this->_SI->data()->fileAccessedTime, TIME_MS_64));
  attr["creation"] = new Variant(new vtime(this->_SI->data()->creationTime, TIME_MS_64));
  /*
  mftData->clusterSize(4096);
  mftData->indexRecordSize(4096);
  mftData->sectorSize(512);
  mftData->mftEntrySize(1024);
  */
  if (!(this->_mft->decode(this->_physOffset))) {
    return attr;
  }

  //  _mft->readHeader();
  while ((attribute = (this->_mft->getNextAttribute()))) {
    std::map<std::string, class Variant *>	attributeMap;
    std::string					attributeFullName;
    std::map<std::string, class Variant *>	attributeHeaderMap;
    
    attribute->readHeader();
    attributeFullName = attribute->getFullName();
    attributeHeaderMap = this->_headerToAttribute(attribute);

    if (attribute->getType() == ATTRIBUTE_STANDARD_INFORMATION) {
      this->_standardInformation(&attributeMap, new AttributeStandardInformation(*attribute));
    }
    DEBUG(INFO, "got name: %s\n", attributeFullName.c_str());
    attributeMap.insert(std::pair<std::string, class Variant *>("Header", new Variant(attributeHeaderMap)));
    attr[attributeFullName] = new Variant(attributeMap);
  }
  return attr;
}

void	NtfsNode::_standardInformation(std::map<std::string, class Variant *> *map, AttributeStandardInformation *nAttr)
{
  std::map<std::string, class Variant *>	flagsMap;

  flagsMap.insert(std::pair<std::string, class Variant *>("Value", new Variant(nAttr->data()->flags)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Read only", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_READ_ONLY) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Hidden", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_HIDDEN) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("System", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SYSTEM) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Archive", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_ARCHIVE) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Device", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_DEVICE) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("#Normal", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SHARPNORMAL) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Temporary", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_TEMPORARY) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Sparse", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SPARSE_FILE) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Reparse point", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_REPARSE_POINT) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Compressed", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_COMPRESSED) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Offline", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_OFFLINE) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Content is not being indexed for faster searches", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_CONTENT_NOT_INDEXED) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Encrypted", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_ENCRYPTED) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Directory", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_DIRECTORY) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Index view", new Variant((nAttr->data()->flags & ATTRIBUTE_SI_FLAG_INDEX_VIEW) > 0)));
  flagsMap.insert(std::pair<std::string, class Variant *>("Unknown flag present", new Variant((nAttr->data()->flags && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_READ_ONLY) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_HIDDEN) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SYSTEM) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_ARCHIVE) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_DEVICE) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SHARPNORMAL) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_TEMPORARY) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_SPARSE_FILE) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_REPARSE_POINT) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_COMPRESSED) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_OFFLINE) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_CONTENT_NOT_INDEXED) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_ENCRYPTED) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_DIRECTORY) && !(nAttr->data()->flags & ATTRIBUTE_SI_FLAG_INDEX_VIEW)))));

  map->insert(_dataToVTime("Creation time", nAttr->data()->creationTime));
  map->insert(_dataToVTime("File altered time", nAttr->data()->fileAlteredTime));
  map->insert(_dataToVTime("MFT altered time", nAttr->data()->mftAlteredTime));
  map->insert(_dataToVTime("File accessed time", nAttr->data()->fileAccessedTime));
  map->insert(std::pair<std::string, class Variant *>("Flags", new Variant(flagsMap)));
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
  /* Issue #80 : GUI API have to provide it (base convertion)
  std::ostringstream	stringBuff;
  stringBuff << value << " (0x" << hex << value << ")";
  return std::pair<std::string, class Variant *>(key, new Variant(stringBuff.str()));*/
  return std::pair<std::string, class Variant *>(key, new Variant(value));
}

Variant	*NtfsNode::_dataToAttr(uint32_t value)
{
  /* Issue #80 : GUI API have to provide it (base convertion)
  std::ostringstream	stringBuff;
  stringBuff << value << " (0x" << hex << value << ")";
  return new Variant(stringBuff.str());*/
  return new Variant(value);
}

std::pair<std::string, class Variant *>	NtfsNode::_dataToAttr(std::string key, uint64_t value)
{
  /* Issue #80 : GUI API have to provide it (base convertion)
  std::ostringstream	stringBuff;
  stringBuff << value << " (0x" << hex << value << ")";
  return std::pair<std::string, class Variant *>(key, new Variant(stringBuff.str()));*/
  return std::pair<std::string, class Variant *>(key, new Variant(value));
}

Variant	*NtfsNode::_dataToAttr(uint64_t value)
{
  /* Issue #80 : GUI API have to provide it (base convertion)
  std::ostringstream	stringBuff;
  stringBuff << value << " (0x" << hex << value << ")";
  return new Variant(stringBuff.str());*/
  return new Variant(value);
}

std::pair<std::string, class Variant *>	NtfsNode::_dataToVTime(std::string key, uint64_t value)
{
  return std::pair<std::string, class Variant *>(key, new Variant(new vtime(value, TIME_MS_64)));
}

std::pair<std::string, class Variant *>	NtfsNode::_dataToAttr(std::string key, uint16_t value)
{
  /* Issue #80 : GUI API have to provide it (base convertion)
  std::ostringstream	stringBuff;
  stringBuff << value << " (0x" << hex << value << ")";
  return std::pair<std::string, class Variant *>(key, new Variant(stringBuff.str()));*/
  return std::pair<std::string, class Variant *>(key, new Variant(value));
}

std::pair<std::string, class Variant *>	NtfsNode::_dataToAttr(std::string key, uint8_t value)
{
  return _dataToAttr(key, (uint16_t)value);
}

void	NtfsNode::fileMapping(FileMapping *fm)
{
  if (_isFile && size()) {
    if (_data->attributeHeader()->nonResidentFlag) {
      DEBUG(CRITICAL, "NtfsNode::fileMapping nonResident\n");
      _offsetFromRunList(fm);
    }
    else {
      DEBUG(CRITICAL, "NtfsNode::fileMapping resident\n");
      _offsetResident(fm);
    }
  }
}

/**
 * Set data chunks for data inside of MFT attribute
 *  Fixups values are present in the last two bytes of sector
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

  DEBUG(CRITICAL, "\tdataStart: 0x%x\n", dataStart);
  DEBUG(CRITICAL, "\tsectorSize - 2: 0x%x\n", _data->getSectorSize() - 2);
#if __WORDSIZE == 64
  DEBUG(CRITICAL, "\tfirst fixup: 0x%lx\n", _physOffset + _data->getFixupOffset(0));
#else
  DEBUG(CRITICAL, "\tfirst fixup: 0x%llx\n", _physOffset + _data->getFixupOffset(0));
#endif

  fm->push(0, firstChunkSize, _node, _data->getOffset());
  fm->push(firstChunkSize, SIZE_2BYTES, _node, _physOffset + _data->getFixupOffset(0));
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
  AttributeData	currentData = *(_data);
  uint16_t	offsetListSize = currentData.getOffsetListSize();

  OffsetRun	*run;

  DEBUG(CRITICAL, "Offset list size: %u\n", offsetListSize);
  while ((currentRunIndex < offsetListSize)) {
    run = currentData.getOffsetRun(currentRunIndex);

    newSize = (run->runLength - registeredClusters) * currentData.clusterSize();

    if (run->runOffset) {						//1.1 + 2.1 + 3.1
      if (currentOffset + newSize > currentData.getSize()) {		//1.1
	if ((currentOffset + newSize) > currentData.getInitSize() && currentData.getSize() > currentData.getInitSize()) {
	  // > initSize, need to create shadow node
	  fm->push(currentOffset, currentData.getInitSize() - currentOffset,
		   _node, run->runOffset * currentData.clusterSize());
	  fm->push(currentOffset + (currentData.getInitSize() - currentOffset),
		   newSize - (currentData.getInitSize() - currentOffset), NULL, 0);
#if __WORDSIZE == 64
	  DEBUG(CRITICAL, "FM0.1 for offset 0x%lx push size 0x%lx at origin offset 0x%lx\n", currentOffset, currentData.getInitSize() - currentOffset, run->runOffset * currentData.clusterSize());
	  DEBUG(CRITICAL, "FM0.1 for offset 0x%lx push size 0x%lx as shadow (empty content)\n", currentOffset + (currentData.getInitSize() - currentOffset), newSize - (currentData.getInitSize() - currentOffset));
#else
	  DEBUG(CRITICAL, "FM0.1 for offset 0x%llx push size 0x%llx at origin offset 0x%llx\n", currentOffset, currentData.getInitSize() - currentOffset, run->runOffset * currentData.clusterSize());
	  DEBUG(CRITICAL, "FM0.1 for offset 0x%llx push size 0x%llx as shadow (empty content)\n", currentOffset + (currentData.getInitSize() - currentOffset), newSize - (currentData.getInitSize() - currentOffset));
#endif
	}
	else {
	  fm->push(currentOffset, newSize - (currentOffset + newSize - currentData.getSize()),
		   _node, run->runOffset * currentData.clusterSize());
#if __WORDSIZE == 64
	  DEBUG(CRITICAL, "FM1.1 for offset 0x%lx push size 0x%lx at origin offset 0x%lx\n", currentOffset, newSize - (currentOffset + newSize - currentData.getSize()), run->runOffset * currentData.clusterSize());
#else
	  DEBUG(CRITICAL, "FM1.1 for offset 0x%llx push size 0x%llx at origin offset 0x%llx\n", currentOffset, newSize - (currentOffset + newSize - currentData.getSize()), run->runOffset * currentData.clusterSize());
#endif
	}
      }
      else {								//2.1 + 3.1
	if ((currentOffset + newSize) > currentData.getInitSize()) {	//2.1
	  // > initSize, need to create shadow node
	  fm->push(currentOffset, currentData.getInitSize() - currentOffset,
		   _node, run->runOffset * currentData.clusterSize());
#if __WORDSIZE == 64
	  DEBUG(CRITICAL, "FM2.1 for offset 0x%lx push size 0x%lx at origin offset 0x%lx\n", currentOffset, currentData.getInitSize() - currentOffset, run->runOffset * currentData.clusterSize());
#else
	  DEBUG(CRITICAL, "FM2.1 for offset 0x%llx push size 0x%llx at origin offset 0x%llx\n", currentOffset, currentData.getInitSize() - currentOffset, run->runOffset * currentData.clusterSize());
#endif
	  fm->push(currentOffset + (currentData.getInitSize() - currentOffset),
		   newSize - (currentData.getInitSize() - currentOffset), NULL, 0);
#if __WORDSIZE == 64
	  DEBUG(CRITICAL, "FM2.1 for offset 0x%lx push size 0x%lx as shadow (empty content)\n", currentOffset + (currentData.getInitSize() - currentOffset), newSize - (currentData.getInitSize() - currentOffset));
#else
	  DEBUG(CRITICAL, "FM2.1 for offset 0x%llx push size 0x%llx as shadow (empty content)\n", currentOffset + (currentData.getInitSize() - currentOffset), newSize - (currentData.getInitSize() - currentOffset));
#endif
	}
	else {								//3.1
	  fm->push(currentOffset, newSize, _node, run->runOffset * currentData.clusterSize());
#if __WORDSIZE == 64
	  DEBUG(CRITICAL, "FM3.1 for offset 0x%lx push size 0x%lx at origin offset 0x%lx\n", currentOffset, newSize, run->runOffset * currentData.clusterSize());
#else
	  DEBUG(CRITICAL, "FM3.1 for offset 0x%llx push size 0x%llx at origin offset 0x%llx\n", currentOffset, newSize, run->runOffset * currentData.clusterSize());
#endif
	}
      }
    }
    else { // shadow							//4.1
      fm->push(currentOffset, newSize, NULL, 0);
#if __WORDSIZE == 64
      DEBUG(CRITICAL, "FM4.1 for offset 0x%lx push size 0x%lx as shadow (empty content)\n", currentOffset, newSize);
#else
      DEBUG(CRITICAL, "FM4.1 for offset 0x%llx push size 0x%llx as shadow (empty content)\n", currentOffset, newSize);
#endif
    }

    currentOffset += (run->runLength - registeredClusters) * currentData.clusterSize();
    registeredClusters = run->runLength;

    currentRunIndex++;
    if (currentRunIndex >= offsetListSize && _dataOffsets.size() > 1) {
      // There are several $DATA attributes, we have to fetch the next one.
      // We also have to take care of $DATA attribute's name because of ADS
      // feature, we should rely of next valid VCN.
#if __WORDSIZE == 64
      DEBUG(CRITICAL, "starting VCN 0x%lx ending VCN 0x%lx\n", currentData.nonResidentDataHeader()->startingVCN, currentData.nonResidentDataHeader()->endingVCN);
#else
      DEBUG(CRITICAL, "starting VCN 0x%llx ending VCN 0x%llx\n", currentData.nonResidentDataHeader()->startingVCN, currentData.nonResidentDataHeader()->endingVCN);
#endif
      _setNextAttrData(fm, currentOffset);
    }
  }
  DEBUG(CRITICAL, "\n");
}

void					NtfsNode::_setNextAttrData(FileMapping *fm, uint64_t totalOffset) {
  std::list<uint64_t>::const_iterator	iter(_dataOffsets.begin());
  std::list<uint64_t>::const_iterator	listend(_dataOffsets.end());
  MftEntry				*externalData;
  VFile					*vfile;
  Attribute				*attribute;
  AttributeData				*data;
  uint64_t				totalSize = _data->getSize();
  uint64_t				initSize = _data->getInitSize();

  if (!_SI || _dataOffsets.size() <= 1) {
    DEBUG(CRITICAL, "No $STANDARD_INFORMATION attribute, returns\n");
    return ;
  }
  // TODO _dataOffsets list should be ordered by VCN, but it seams to be done
  // in $ATTRIBUTE_LIST.

  // Init mft decoder
  vfile = _node->open();
  externalData = new MftEntry(vfile);
  // Init sizes from previously registered attribute _data
  externalData->clusterSize(_data->clusterSize());
  externalData->indexRecordSize(_data->indexRecordSize());
  externalData->sectorSize(_data->sectorSize());
  externalData->mftEntrySize(_data->mftEntrySize());

  // First $DATA attribute is _data, has already been mapped above,
  // so increment iter.
  ++iter;
  while (iter != listend) {
    if (externalData->decode(*iter)) {
      while ((attribute = externalData->getNextAttribute())) {
	attribute->readHeader();
	if (attribute->getType() == ATTRIBUTE_DATA) {
	  data = new AttributeData(*attribute);
#if __WORDSIZE == 64
	  DEBUG(CRITICAL, "data @ 0x%lx starting VCN 0x%lx ending VCN 0x%lx\n", *iter, data->nonResidentDataHeader()->startingVCN, data->nonResidentDataHeader()->endingVCN);
#else
	  DEBUG(CRITICAL, "data @ 0x%llx starting VCN 0x%llx ending VCN 0x%llx\n", *iter, data->nonResidentDataHeader()->startingVCN, data->nonResidentDataHeader()->endingVCN);
#endif
	  // TODO Same code as in _offsetFromRunList( merge in one func ?
	  uint16_t	currentRunIndex = 0;
	  uint64_t	currentOffset = 0;
	  uint64_t	newSize;
	  uint16_t	offsetListSize = data->getOffsetListSize();
	  uint64_t	registeredClusters = 0;

	  OffsetRun	*run;

	  DEBUG(CRITICAL, "Offset list size: %u\n", offsetListSize);
	  while ((currentRunIndex < offsetListSize)) {
	    run = data->getOffsetRun(currentRunIndex);
	    
	    newSize = (run->runLength - registeredClusters) * data->clusterSize();
	    if (run->runOffset) {
	      if (currentOffset + newSize > totalSize) {
		// XXX if > initSize, need to create shadow node
		fm->push(totalOffset, newSize - (currentOffset + newSize - totalSize),
			 _node, run->runOffset * data->clusterSize());
#if __WORDSIZE == 64
		DEBUG(CRITICAL, "FM1.2 for offset 0x%lx push size 0x%lx at origin offset 0x%lx\n", totalOffset, newSize - (currentOffset + newSize - totalSize), run->runOffset * data->clusterSize());
#else
		DEBUG(CRITICAL, "FM1.2 for offset 0x%llx push size 0x%llx at origin offset 0x%llx, runLength 0x%x clustSize 0x%x\n", totalOffset, newSize - (currentOffset + newSize - totalSize), run->runOffset * data->clusterSize(), run->runLength, data->clusterSize());
#endif
	      }
	      else {
		if ((currentOffset + newSize) > initSize) {
		  // > initSize, need to create shadow node
		  fm->push(totalOffset, initSize - currentOffset,
			   _node, run->runOffset * data->clusterSize());
#if __WORDSIZE == 64
		  DEBUG(CRITICAL, "FM2.2 for offset 0x%lx push size 0x%lx at origin offset 0x%lx\n", totalOffset, initSize - currentOffset, run->runOffset * data->clusterSize());
#else
		  DEBUG(CRITICAL, "FM2.2 for offset 0x%llx push size 0x%llx at origin offset 0x%llx\n", totalOffset, initSize - currentOffset, run->runOffset * data->clusterSize());
#endif
		  fm->push(totalOffset + (initSize - currentOffset),
			   newSize - (initSize - currentOffset), NULL, 0);
#if __WORDSIZE == 64
		  DEBUG(CRITICAL, "FM2.2 for offset 0x%lx push size 0x%lx as shadow (empty content)\n", totalOffset + (initSize - currentOffset), newSize - (initSize - currentOffset));
#else
		  DEBUG(CRITICAL, "FM2.2 for offset 0x%llx push size 0x%llx as shadow (empty content)\n", totalOffset + (initSize - currentOffset), newSize - (initSize - currentOffset));
#endif
		}
		else {
		  fm->push(totalOffset, newSize, _node, run->runOffset * data->clusterSize());
#if __WORDSIZE == 64
		  DEBUG(CRITICAL, "FM3.2 for offset 0x%lx push size 0x%lx at origin offset 0x%lx\n", totalOffset, newSize, run->runOffset * data->clusterSize());
#else
		  DEBUG(CRITICAL, "FM3.2 for offset 0x%llx push size 0x%llx at origin offset 0x%llx\n", totalOffset, newSize, run->runOffset * data->clusterSize());
#endif
		}
	      }
	    }
	    else { // shadow
	      fm->push(totalOffset, newSize, NULL, 0);
#if __WORDSIZE == 64
	      DEBUG(CRITICAL, "FM4.2 for offset 0x%lx push size 0x%lx as shadow (empty content)\n", totalOffset, newSize);
#else
	      DEBUG(CRITICAL, "FM4.2 for offset 0x%llx push size 0x%llx as shadow (empty content)\n", totalOffset, newSize);
#endif
	    }
	    
	    currentOffset += (run->runLength - registeredClusters) * data->clusterSize();
	    totalOffset += (run->runLength - registeredClusters) * data->clusterSize();
	    //currentOffset += (run->runLength) * data->clusterSize();
	    registeredClusters = run->runLength;
	    
	    currentRunIndex++;
	  }
	  //delete data;
	  DEBUG(CRITICAL, "\n");
	  //	  throw("yeah");
	  break;
	}
      }
    }
    ++iter;
  }
}


