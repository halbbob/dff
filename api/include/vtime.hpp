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
 *  Solal J. <sja@digital-forensic.org>
 */

#ifndef __VTIME_HPP__
#define __VTIME_HPP__

#include "export.hpp"

#ifndef WIN32
# include <stdint.h>
#else
# include "wstdint.h"
#endif

#include <stdlib.h>
#include <vector>
#include <string>



class vtime
{
public:
  EXPORT		vtime();
  EXPORT virtual	~vtime();
  EXPORT 		vtime(int, int, int, int, int, int, int);
  int 			year;	
  int 			month;	
  int 			day;	
  int 			hour;	
  int 			minute;	
  int 			second;	
  int 			usecond; 
  int			wday;
  int			yday;	
  int			dst;
};


typedef struct	tm_s
{
  uint32_t	tm_year;
  uint32_t	tm_mon;
  uint32_t	tm_mday;
  uint32_t	tm_hour;
  uint32_t	tm_min;
  uint32_t	tm_sec;
}		tm_t;

class	Time
{
public:
  EXPORT Time(uint64_t timestamp);
  EXPORT ~Time();

  EXPORT const tm_t *	tm() const;
  EXPORT vtime *	Vtime() const;
  EXPORT void		setVtime(vtime * t);

private:
  uint32_t	__february(uint32_t years);
  uint32_t	__calc_year();
  void		__convert();

  uint32_t	__timestamp;
  tm_t *	__tm;
  vtime *	__vtime;
  std::vector<std::pair<std::string, uint32_t> > __months_days;
};




#endif

