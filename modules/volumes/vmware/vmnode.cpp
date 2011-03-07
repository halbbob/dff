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
 *  Jeremy MOUNIER <fba@digital-forensic.org>
 */

#include "vmnode.hpp"

VMNode::VMNode(std::string Name, uint64_t size, Node* parent, VMware* vm, Link *lnk): Node(Name, size, parent, vm)
{

  this->_vm = vm;
  this->_lnk = lnk;
  this->_cid = this->_lnk->getCID();
  this->_links = this->_vm->getLinksFromCID(this->_cid);
  this->setFile();
  // std::cout << "Create Node with CID : " << this->_cid << std::endl;  
  //  std::cout << "Link Size : " << this->_links.size() << std::endl;  
  
  // for( list<Link*>::iterator lnk=this->_links.begin(); lnk!=this->_links.end(); ++lnk)
  //   {
  //     std::vector<Extent*> extents = (*lnk)->getExtents();
  //     std::cout << "LINK CID : " << (*lnk)->getCID() << std::endl;  

  //     for( vector<Extent*>::iterator ext=extents.begin(); ext!=extents.end(); ++ext)
  // 	{
  // 	  std::cout << "Extent node : " << (*ext)->vmdk->name() << std::endl;  
  // 	}
  //   }

  this->_baseLink = this->getBaseLink();
}

VMNode::~VMNode()
{
}

// avoir une list de chaque link qui compose la node (dans lordre c a dire base a la fin)
// on parse les extent pour chaque link
// pour chaque link on va lire extent[cp]
// on renvoi la premiere valeur != 0
// sinon on renvoi 0 sur le base link

Link	*VMNode::getBaseLink()
{
  for( list<Link*>::iterator lk=this->_links.begin(); lk!=this->_links.end(); ++lk)
    {
      if ((*lk)->isBase())
	return (*lk);
    }
}


void VMNode::fileMapping(FileMapping *fmap)
{
  // Get extents from first Link
  std::vector<Extent*> extents = this->_baseLink->getExtents();
  // Get number of extents
  uint32_t	nextents = extents.size();
  uint32_t	curextent = 0;

  uint64_t	voffset = 0;
  uint64_t	vextoffset = 0;

  uint64_t	GDEOffset;
  uint64_t	GTOffset;

  uint64_t	currentGDE = 0;

  int		mapcheck;
  // Parse All extents

  std::cout << "N of Extents : " << nextents << " GDEntries " << extents[curextent]->GDEntries << " GTEntries " << extents[curextent]->GTEntries<< std::endl;

  while (curextent < nextents)
    {
      currentGDE = 0;
      vextoffset = 0;
      while (currentGDE < extents[curextent]->GDEntries)
  	{
	  //	  std::cout << "Current GDE parsed : " << currentGDE << std::endl;
  	  mapcheck = this->mapGTGrains(currentGDE, curextent, fmap, &voffset, &vextoffset, extents[curextent]->GTEntries);
	  //	  if mapcheck
  	  currentGDE++;
  	}
      //      std::cout << "Current Extent : " << curextent << std::endl;      
      //      std::cout << "voffset " << voffset << std::endl;
      curextent++;
    }

  //  return fmap;
}

Link	*VMNode::getDeltaLink(uint64_t currentGDE, uint32_t currentGTE, uint32_t curextent)
{
  uint64_t	GTOffset;
  uint32_t	GTEntry;
  uint64_t	GDEOffset;

  for( list<Link*>::iterator lk=this->_links.begin(); lk!=this->_links.end(); ++lk)
    {
      std::vector<Extent*>	extents = (*lk)->getExtents();
      Extent	*ext = extents[curextent];

      GDEOffset = (ext->sectorRGD * SECTOR_SIZE) + (currentGDE * 4);

      GTOffset = this->getGT(GDEOffset, ext);
      
      GTEntry = this->readGTEntry(GTOffset, currentGTE, ext);
      if (GTEntry != 0)
	{
	  // if (curextent == 9)
	  //   {
	  //	  std::cout << "->In Sup Link - GDE : " << currentGDE << " GTE : " << currentGTE << std::endl;
	  //     std::cout << "---> GTentry : " << GTEntry << " in " << ext->vmdk->name() <<std::endl;
	  //   }
	  return (*lk);
	}
    }
  //  if (curextent == 0 && currentGDE == 0)
  //    std::cout << "GetDeltaLink:returnBaseLink " << std::endl;
  return this->_baseLink;
}

uint32_t	VMNode::readGTEntry(uint64_t GTEOffset, uint32_t currentGTE, Extent *ext)
{
  uint32_t	GTEntry;

  try
    {
      ext->vfile->seek(GTEOffset + (currentGTE * 4));
      ext->vfile->read(&GTEntry, sizeof(unsigned int));
      
    }
  catch (envError & e)
    {
      std::cerr << "Error reading Entry : arg->get(\"parent\", &_node) failed." << endl;
      throw e;
    }

  return GTEntry;
}

//=========================

// Get GT Start Offset from a GD Entry
uint64_t	VMNode::getGT(uint64_t GDEOffset, Extent* ext)
{
  uint64_t	GTOffset;
  uint32_t	GDEntry; // ok 

  try
    {
      ext->vfile->seek(GDEOffset);
      ext->vfile->read(&GDEntry, sizeof(unsigned int));
    }
  catch (envError & e)
    {
      std::cerr << "Error reading Entry : arg->get(\"parent\", &_node) failed." << endl;
      throw e;
    }
  GTOffset = GDEntry * SECTOR_SIZE;
  return GTOffset;
    

}


int VMNode::mapGTGrains(uint64_t currentGDE, uint32_t curextent, FileMapping *fm, uint64_t *voffset, uint64_t *vextoffset, uint64_t GTEntries)
{

  uint64_t	grainOffset;
  uint32_t	GTEntry;

  uint64_t	currentGTE = 0;
  uint64_t	GDEOffset;
  uint32_t	grainSize;
  uint64_t	GTOffset;

  while (currentGTE < GTEntries)
    {

      Link *dlink = this->getDeltaLink(currentGDE, currentGTE, curextent);

      vector<Extent *> extents = dlink->getExtents();
      Extent *ext = extents[curextent];

      if (*vextoffset < (ext->sectors * SECTOR_SIZE))
	{
	  GDEOffset = (ext->sectorRGD * SECTOR_SIZE) + (currentGDE * 4);

	  GTOffset = this->getGT(GDEOffset, ext);
	  GTEntry = this->readGTEntry(GTOffset, currentGTE, ext);
	  
	  grainSize = (ext->sectorsPerGrain * SECTOR_SIZE);
	  	  
	  grainOffset = (uint64_t)(GTEntry) * SECTOR_SIZE;

	  if (GTEntry != 0)
	    {
	      //	      if (*voffset >= 0x43200000 && *voffset < 0x43250000)
	      //		std::cout << "-------> In mapGTGrains : " << ext->vmdk->name() << " @ GTEntry : " << GTEntry << " Grain Offset : " << grainOffset << " Current GDE " << currentGDE << " CurrentGTE " << currentGTE << " voffset " << *voffset << " GTOffset " << GTOffset << " GDEOffset " << GDEOffset << std::endl;
	      //grainOffset = GTEntry * SECTOR_SIZE;
	      fm->push(*voffset, grainSize, ext->vmdk, grainOffset);
	    }
	  else
	    fm->push(*voffset, grainSize);
	  
	  *voffset += grainSize;
	  *vextoffset += grainSize;
	  currentGTE += 1;
	}
      else
	{
	  //	  std::cout << "capacity exceded in  " << ext->vmdk->name() << std::endl;	  
	  return 0;
	}
    }
  return 1;

}
