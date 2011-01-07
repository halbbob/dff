/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __DEVENTHANDLER_HPP__
#define __DEVENTHANDLER_HPP__

#ifndef WIN32
#include <stdint.h>
#else
#include "wstdint.h"
#endif
#include "export.hpp"
#include <iostream>
#include <iomanip>
#include <vector>

enum event {OPEN = 0, CLOSE = 1, READ = 2, WRITE = 3, SEEK = 4, OTHER = 5};

typedef struct	s_DEvent
{
  event		type;
  uint64_t	seek;
}		DEvent;

class DEventHandler
{
private:
  std::vector<class DEventHandler *>	watchers;
public:
  EXPORT DEventHandler();
  EXPORT virtual		~DEventHandler() {};
  EXPORT virtual void		Event(DEvent *e) = 0;
  EXPORT bool			connection(class DEventHandler *obs);
  EXPORT bool			deconnection(class DEventHandler *obs);
  EXPORT bool			notify(DEvent *e);
};

#endif
