/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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
 *  Solal J. <sja@digital-forensic.org>
 */

#include "vtime.hpp"

vtime::vtime(uint64_t value, uint32_t type = 0) 
{
  if (value > 0)
  {
    struct tm   *date;
    if (type == TIME_MS)
    {
      value -= NANOSECS_1601_TO_1970;
      value /= 10000000;
    }  
    date = gmtime((time_t *)&value);
    this->year = date->tm_year + 1900;
    this->month = date->tm_mon + 1;
    this->day = date->tm_mday;
    this->hour = date->tm_hour;
    this->minute = date->tm_min;
    this->second = date->tm_sec;
    this->dst = date->tm_isdst;
    this->wday = date->tm_wday;
    this->yday = date->tm_yday;
    this->usecond = 0;
  }
  else 
   year = month = day = hour = minute = second = usecond = 0; 
}

vtime::vtime()
{
   year = month = day = hour = minute = second = usecond = 0; 
}

vtime::~vtime()
{
}

vtime::vtime(int y, int mo, int d, int h, int mi, int s, int us)
{
   year = y; month = mo; day = d; hour = h; minute = mi; second = s; 
   usecond = us; 
}

