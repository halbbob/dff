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
 *  MOUNIER Jeremy <jmo@digital-forensic.org>
 *
 */

#include <time.h>
#include <string.h>

#include "vmware.hpp"
#include "vmdk.hpp"
#include "diskDescriptor.hpp"

VMware::VMware() : mfso("vmware")
{
  //    _forceVmdkReconstruction = false;
  //  _storageVolumeSize = 0;

}

VMware::~VMware()
{
}

void	VMware::start(std::map<std::string, Variant*> args)
{
  int		err;
  int		extcp;
  int		ft;
  std::map<std::string, Variant*>::iterator	it;

  it = args.find("vmdkroot");
  if (it != args.end())
    this->_vmdkroot = it->second->value<Node*>();
  else
    throw (std::string("Could not load node : arg->get(\"parent\", &_node) failed."));
  
  this->_rootdir = this->_vmdkroot->parent();
  err = this->createLinks(_vmdkroot, "0");
  std::cout << "ERROR : " << err << std::endl;
  if (err != -1)
    {
      //      std::cout << "Links : " << this->_links.size() << std::endl;
      //      this->res->add_const("Links", this->_links.size());
      this->createNodes();
    }
  
}


Node	*VMware::getParentVMDK(string parentFileName)
{
  Node *parent = this->_vmdkroot->parent();
  
  //  std::cout << "parentFileName :  " << parentFileName << std::endl;
  //  std::cout << "parent :  " << parent->name() << std::endl;
  
  std::vector<Node *>next = parent->children();
  
  for( std::vector<Node*>::iterator in=next.begin(); in!=next.end(); ++in)
    {
      if ((*in)->name() == parentFileName)
	{
	  std::cout << "founded " << (*in)->name() << std::endl;
	  return (*in);
	}
    }
   return NULL; 
}

/* Detect VMDK type: Storage Volume | Text Descriptor*/
int	VMware::detectDiskDescriptor(Node *vmdk)
{
  unsigned int	flag;
  VFile		*vfile = vmdk->open();
  sparseExtentHeader header;
  
  try
    {
      vfile->seek(0);
      vfile->read(&flag, sizeof(unsigned int));
    }
  catch (envError & e)
    {
      std::cerr << "Error reading vmdk disk descriptor : arg->get(\"parent\", &_node) failed." << endl;
      throw e;
    }
  
  if (flag == VMDK_DISK_DESCRIPTOR)
    {
      vfile->close();
      return 0;
    }
  else if (flag == VMDK_SPARSE_MAGICNUMBER)
    { 
      /** Read VMDK _Header and get Disk Descriptor sector if present**/
      try
	{
	  vfile->seek(0);
	  vfile->read(&header, sizeof(SparseExtentHeader));
	  vfile->close();
	}
      catch (envError & e)
	{
	  std::cerr << "Error reading Header : arg->get(\"parent\", &_node) failed." << endl;
	  throw e;
	}
      if (header.descriptorOffset != 0)
	  return 1;
    }
  else
    {
      vfile->close();
      return -1;
    }
}

int	VMware::createLinks(Node *vmdkroot, string pcid)
{
  int		err;
  int		ft;
  
  if (pcid != CID_NOPARENT)
    {
      
      ft = this->detectDiskDescriptor(vmdkroot);
      
      if (ft >= 0)
	{
	  diskDescriptor *dd = new diskDescriptor(vmdkroot, ft);
	  
	  string parentFileName = dd->parentFileName();

	  string cid = dd->getCID();
	  string npcid = dd->getPCID();

	  Link *lnk = new Link(dd, ft, vmdkroot);
	  err = lnk->listExtents();
	  // std::cout << "CID :  " << cid << std::endl;
	  // std::cout << "PCID :  " << npcid << std::endl;
	  _links[cid] = lnk;

	  if (err != -1 && npcid != CID_NOPARENT)
	    {
	      Node *parent = getParentVMDK(parentFileName);
	      if (parent != NULL)
		this->createLinks(parent, npcid);
	      else
		return -1;
	    }
	}
      else
	return -1;
    }
  return 1;
}
  
  // ================================================================
  
  int	VMware::createNodes()
{

  this->_baseroot = new Node("Baselink");
  

  if (this->_links.size() > 1)
    this->_snaproot = new Node("Snapshots", 0, _vmdkroot);

  for( map<string,Link*>::iterator ii=_links.begin(); ii!=_links.end(); ++ii)
      {
      std::string id = ii->first;
      Link *lnk = ii->second;

      uint64_t vs = lnk->volumeSize();

      if (!lnk->isBase())
	{
	  Node *bnode = new Node(id, 0, this->_snaproot);
	  Node *vnode = new VMNode("VirtualHDD", vs, bnode, this, lnk);
	  this->_baseNodes.push_back(bnode);
	}
      else
	{
	  Node *vnode = new VMNode("VirtualHDD", vs, _baseroot, this, lnk);
	  this->_baseNodes.push_back(vnode);
	}
    }

  this->registerTree(_vmdkroot, _baseroot);
  return (0);
}

list<Link*>	VMware::getLinksFromCID(string cid)
{
  Link		*tmplnk;
  list<Link*>	res;
  string	ccid = cid;
  string	pcid = "";

  while (pcid != CID_NOPARENT)
    {
      tmplnk = this->_links[ccid];
      pcid.clear();
      pcid = tmplnk->getPCID();
      ccid.clear();
      ccid = pcid;
      res.push_back(tmplnk);
    }
  return res;
}

