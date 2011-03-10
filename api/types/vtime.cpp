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

vtime::~vtime()
{
}

vtime::vtime(int y, int mo, int d, int h, int mi, int s, int us)
{
   year = y; month = mo; day = d; hour = h; minute = mi; second = s; 
   usecond = us; 
}


Time::Time(uint64_t timestamp) : __months_days(12), __tm(NULL), __vtime(NULL)
{
  this->__timestamp = timestamp;
  this->__tm = new tm_t;
  this->__vtime = new vtime();

  __months_days[0] = std::make_pair("Jan", 31);
  __months_days[1] = std::make_pair("Feb", 28);
  __months_days[2] = std::make_pair("Mar", 31);
  __months_days[3] = std::make_pair("Apr", 30);
  __months_days[4] = std::make_pair("May", 31);
  __months_days[5] = std::make_pair("Jun", 30);
  __months_days[6] = std::make_pair("Jul", 31);
  __months_days[7] = std::make_pair("Aug", 31);
  __months_days[8] = std::make_pair("Sep", 30);
  __months_days[9] = std::make_pair("Oct", 31);
  __months_days[10] = std::make_pair("Nov", 30);
  __months_days[11] = std::make_pair("Dec", 31);

  __convert();
}

Time::~Time()
{
}

uint32_t	Time::__february(uint32_t years)
{
  if (!(years % 4) && (years % 100))
    return 29;
  if (!(years % 400))
    return 29;
  return 28;
}

void	Time::__convert()
{
  uint32_t years = __calc_year();
  uint32_t leap_year = (years - 1969) / 4;
  uint32_t days_since_epoch = __timestamp / 86400;
  uint32_t day_in_year = (days_since_epoch - leap_year) % 365;
  uint32_t month = 0;
  uint32_t nb_day_feb = 0;

  // calculate month and day in month
  unsigned int	tot = 0, tmp = day_in_year;  
  unsigned int i = 0;
  while (tot < day_in_year)
    {
      if (i != 1) // not february
	{
	  tot += __months_days[i].second;
	  tmp -= __months_days[i].second;
	}
      else
	{
	  nb_day_feb = __february(years);
	  tot += nb_day_feb;
	  tmp -= nb_day_feb;
	}
      month++;
      i++;
    }
  if (i && ((i - 1) == 1))
    tmp += nb_day_feb + 1;
  else if (i)
    tmp += __months_days[i - 1].second + 1;

  uint32_t sec_in_cur_day = __timestamp - (days_since_epoch * 86400);
  uint32_t hours = sec_in_cur_day / 3600;
  uint32_t no_idea = sec_in_cur_day - (hours * 3600);
  uint32_t min = no_idea / 60;
  uint32_t sec = no_idea - (min * 60);

  __tm->tm_year = __vtime->year = years;
  __tm->tm_mon = __vtime->month = month;
  __tm->tm_mday = __vtime->day = tmp;
  __tm->tm_hour = __vtime->hour = hours;
  __tm->tm_min = __vtime->minute = min;
  __tm->tm_sec = __vtime->second = sec;
}

const tm_t *	Time::tm() const
{
  return this->__tm;
}

vtime *	Time::Vtime() const
{
  return this->__vtime;
}

uint32_t	Time::__calc_year()
{
  uint32_t	year = 0;
  int64_t	tmp = __timestamp;

  while (tmp >= (365 * 24 * 3600))
    {
      if (__february(year + 1970) == 28)
	tmp -= (365 * 24 * 3600);
      else
	tmp -= (366 * 24 * 3600);
      ++year;
    }
  return year + 1970;
}

void		Time::setVtime(vtime * t)
{
  t->year = __vtime->year;
  t->month = __vtime->month;
  t->day = __vtime->day;
  t->hour = __vtime->hour;
  t->minute = __vtime->minute;
  t->second = __vtime->second;
}
