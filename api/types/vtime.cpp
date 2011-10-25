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

vtime::vtime()
{
  year = month = day = hour = minute = second = usecond = 0; 
}

vtime::vtime(int y, int mo, int d, int h, int mi, int s, int us)
{
  year = y; month = mo; day = d; hour = h; minute = mi; second = s; 
  usecond = us; 
}


vtime::vtime(uint16_t dos_time, uint16_t dos_date)
{
  this->day = (dos_date & 31);
  this->month = ((dos_date >> 5) & 15);
  this->year = ((dos_date >> 9) + 1980);

  if (dos_time != 0)
    {
      this->second = (dos_time & 31) * 2;
      this->minute = ((dos_time >> 5) & 63);
      this->hour = (dos_time >> 11);
    }
  else
    {
      this->second = 0;
      this->minute = 0;
      this->hour = 0;
    }
}

vtime::vtime(uint64_t value, int type = 0) 
{
  if (value > 0)
    {
      struct tm   *date;
      if (type == TIME_MS_64)
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

vtime::vtime(std::string ts)
{
  size_t			pos;
  size_t			opos;

  opos = 0;
  pos = ts.find("-");
  std::istringstream(ts.substr(0, pos)) >> this->year;
  opos = pos + 1;
  pos = ts.find("-", opos);
  std::istringstream(ts.substr(opos, pos-opos)) >> this->month;
  opos = pos + 1;
  pos = ts.find("T", opos);
  std::istringstream(ts.substr(opos, pos-opos)) >> this->day;
  opos = pos + 1;
  pos = ts.find(":", opos);
  std::istringstream(ts.substr(opos, pos-opos)) >> this->hour;
  opos = pos + 1;
  pos = ts.find(":", opos);
  std::istringstream(ts.substr(opos, pos-opos)) >> this->minute;
  std::istringstream(ts.substr(pos+1)) >> this->second;
  this->usecond = 0;
}

bool	vtime::operator==(vtime* v)
{
  if (v != NULL)
    return ((this->year == v->year) && 
	    (this->month == v->month) &&
	    (this->day == v->day) &&
	    (this->hour == v->hour) &&
	    (this->minute == v->minute) &&
	    (this->second == v->second) &&
	    (this->usecond == v->usecond));
  else
    return false;
}

bool	vtime::operator!=(vtime* v)
{
  return !(this->operator==(v));
}

bool	vtime::operator>(vtime* v)
{
  if (v != NULL)
    return ((this->year > v->year) || ((this->year == v->year) && ((this->month > v->month) || ((this->month == v->month) && ((this->day > v->day) || ((this->day == v->day) && ((this->hour > v->hour) || ((this->hour == v->hour) && ((this->minute > v->minute) || ((this->minute == v->minute) && ((this->second > v->second) || ((this->second == v->second) && (this->usecond > v->usecond)))))))))))));
  else
    return true;
}

bool	vtime::operator<(vtime* v)
{
  return !(this->operator>(v));
}

bool	vtime::operator>=(vtime* v)
{
  if (v != NULL)
    return ((this->year > v->year) || ((this->year == v->year) && ((this->month > v->month) || ((this->month == v->month) && ((this->day > v->day) || ((this->day == v->day) && ((this->hour > v->hour) || ((this->hour == v->hour) && ((this->minute > v->minute) || ((this->minute == v->minute) && ((this->second > v->second) || ((this->second == v->second) && ((this->usecond > v->usecond) || (this->usecond == v->usecond))))))))))))));
  else
    return true;
}

bool	vtime::operator<=(vtime* v)
{
  return !(this->operator>=(v));
}

vtime::~vtime()
{
}

