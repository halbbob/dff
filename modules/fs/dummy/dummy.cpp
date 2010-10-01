#include <iostream>
#include "dummy.hpp"
#include "DummyNode.hpp"
 
Dummy::Dummy() : mfso("Dummy") /* mfso constructor requires a std::string, the name of the module. */
{
}
 
Dummy::~Dummy()
{
}
 
void    Dummy::start(argument * args)
{
  try
    {
      
      /* get the parent node */
      args->get("parent", &node);
 
      /* open the node to get a vfile on which we will be able to seek / read */
      vfile = node->open();
 
      /* Creation of the root node of the tree view we are about to build in the
          Dummy module. The fact that it is our "root node" is indicated by the NULL
          parameter.
      */
      root_node = new DummyNode("Dummy", 0, NULL, this, 0);
 
      /* Here should be the code of the module. */
      uint8_t *	name_entries = (uint8_t *)operator new(3 * sizeof(entry_t));
      entry_t * entry = (entry_t *)name_entries;
      vfile->read(name_entries, 48);
      
      for (unsigned int i = 0; i < 3; i++)
	{
	  DummyNode * d_node
	    = new DummyNode(std::string((char *)entry[i].name, 8), // 8 characters names
			    entry[i].size, root_node, this, i * 16);
	}

 
      /* Once the code has finished to be executed, we need to register the tree we built */
      this->registerTree(node, root_node); 
    }
  catch (envError & e) // catch blocks in case of exception
    {
      std::cerr << "Dummy::start() : envError Exception caught : \n\t ->"
                << e.error  << std::endl;
    }
  catch (vfsError & e)
    {
      std::cerr << "Dummy::start() :  vfsError exeption caught :"
                << std::endl << "\t -> " << e.error << std::endl;
    }
  catch (std::exception & e)
    {
      std::cerr << "Dummy::start() : std::exception caught :\n\t -> "
                << e.what() << std::endl;
    }
  catch (...)
    {
      std::cerr << "Dummy::start() : unknown exception caught."
                << std::endl;
    }
}
