
#ifndef DUMMY_NODE_H_
#define DUMMY_NODE_H_

#include "dummy.hpp"
#include "node.hpp"

class	DummyNode : public Node
{
 public:
  DummyNode(std::string name, uint64_t size = 0, Node * parent = NULL,
	    Dummy * fsobj = NULL, uint32_t n_entry_addr = 0);
  ~DummyNode();

  virtual void 	fileMapping(FileMapping* fm);
  virtual void	extendedAttributes(Attributes* attr);

  void		modifiedTime(vtime * t);
  void		accessedTime(vtime * t);
  void		createdTime(vtime * t);
  void		changedTime(vtime * t);

private :
  uint32_t	__n_entry_addr;
  Dummy *	__dummy;
};

#endif /* DUMMY_NODE  */
