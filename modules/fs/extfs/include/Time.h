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
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

#ifndef TIME_H_
#define TIME_H_

#ifndef WIN32
#include <stdint.h>
#else
#include "wstdint.h"
#endif


#include "vtime.hpp"

class	Time
{
public :
  Time(uint32_t c_time);
  ~Time();

  vtime *	v_time() const;

private :
  uint32_t	__ctime;
  void		__convert();
  vtime *	__vtime;
  uint32_t	__year;
  uint32_t	__month;
  uint32_t	__day;
  uint32_t	__hour;
  uint32_t	__min;
  uint32_t	__sec;
};

#endif
