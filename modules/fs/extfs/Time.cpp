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

#include <iostream>

#include "include/Time.h"

Time::Time(uint32_t c_time)
{
  __ctime = c_time;
  __convert();
}

// 1280480510
// le 30/7/2010 à 11:01:50 

Time::~Time()
{
}
vtime *	Time::v_time() const
{
  return __vtime;
}

void		Time::__convert()
{
  uint32_t	t = __ctime;

  __year = __ctime / (24 * 3600 * 365);

  t = __ctime - __year * (24 * 3600 * 365);
  __year += 1970;
  std::cout << "year : " << __year << std::endl;

  __month = t /  ((7 * (24 * 3600 * 31)) + (28 * 3600 * 24) +
		  (4 * (24 * 3600 * 30)));
  std::cout << "t : " << t << std::endl;

  std::cout << "m : " << ((7 * (24 * 3600 * 31)) + (28 * 3600 * 24) +
			  (4 * (24 * 3600 * 30))) << std::endl;

  t %= (7 * (24 * 3600 * 31) + 28 * 3600 * 24 + 
	4 * (24 * 3600 * 30));

  __day = t / (24 * 3600);
  __month = __day / 30;
  __day = t - __month * (24 * 3600);
  __day /= (24 * 3600);
  std::cout << "month : " << __month << std::endl;
  std::cout << "days : " << __day << std::endl;
}
