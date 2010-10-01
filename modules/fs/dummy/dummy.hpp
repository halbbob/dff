#ifndef __DUMMY_H_
# define __DUMMY_H_
 
#include "type.hpp"
#include "vfs.hpp"
#include "argument.hpp"
#include "mfso.hpp"

typedef struct entry_s
{
  uint16_t	offset;
  uint8_t	name[8];
  uint16_t	size;
  uint32_t	fragment;
}		entry_t;
 
class   Dummy : public mfso
{
public:
  Dummy();                                 
  ~Dummy();
 
  /*
     The paramters "arg" of type arguments * contains the list of arguments which were past
     to the module (graphically or in command line). When the module is used, the "start"
     method is called.
  */
  virtual void          start(argument *arg);

  VFile *		vfile;
  class DummyNode *	root_node;
  Node *		node;
};
 
#endif /* __DUMMY_H_ */
