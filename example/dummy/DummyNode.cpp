#include "DummyNode.hpp"

DummyNode::DummyNode(std::string name, uint64_t size, Node* parent,
		     Dummy * fsobj, uint32_t n_entry_addr)
  : Node (name, size, parent, fsobj)
{
  __n_entry_addr = n_entry_addr;
  __dummy = fsobj;
}

DummyNode::~DummyNode()
{
}

void	DummyNode::fileMapping(FileMapping* fm)
{
  uint8_t * entry = (uint8_t *)operator new(sizeof(entry_t));
  entry_t * n_entry = (entry_t *)entry;

  __dummy->vfile->seek(__n_entry_addr);
  __dummy->vfile->read(entry, 16); // 16 is the size of an entry
  fm->push(0, (n_entry->size <= 16 ? n_entry->size : 16) ,
	   __dummy->node, n_entry->offset);
  if (n_entry->size > 16)
    fm->push(16, n_entry->size - 16, __dummy->node, n_entry->fragment);
}

void	DummyNode::extendedAttributes(Attributes* attr)
{
  attr->push("Extended attributes",
	     new Variant("NO extended attributes"));
}

void		DummyNode::modifiedTime(vtime * t)
{
}

void		DummyNode::accessedTime(vtime * t)
{
}

void		DummyNode::createdTime(vtime * t)
{ 
}

void		DummyNode::changedTime(vtime * t)
{ 
}
