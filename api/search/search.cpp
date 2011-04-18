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
 *  Frederic B. <fba@digital-forensic.org>
 */

#include "search.hpp"

FastSearch::FastSearch()//: SearchAlgorithm()
{
}

FastSearch::~FastSearch()
{
}

int32_t		FastSearch::find(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard)
{
  if (wildcard == '\0')
    return fastsearch(haystack, hslen, needle, ndlen, 1, FAST_SEARCH);
  else
    {
      if (fastsearch(needle, ndlen, &wildcard, 1, 1, FAST_SEARCH) == -1)
	return fastsearch(haystack, hslen, needle, ndlen, 1, FAST_SEARCH);
      else
	return wfastsearch(haystack, hslen, needle, ndlen, wildcard, 1, FAST_SEARCH);
    }
}


int32_t		FastSearch::rfind(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard)
{
  if (wildcard == '\0')
    return fastsearch(haystack, hslen, needle, ndlen, 1, FAST_RSEARCH);
  else
    {
      if (fastsearch(needle, ndlen, &wildcard, 1, 1, FAST_SEARCH) == -1)
	return fastsearch(haystack, hslen, needle, ndlen, 1, FAST_RSEARCH);
      else
	return wfastsearch(haystack, hslen, needle, ndlen, wildcard, 1, FAST_RSEARCH);
    }
}


int32_t       FastSearch::count(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard, int32_t maxcount)
{
  if (wildcard == '\0')
    return fastsearch(haystack, hslen, needle, ndlen, maxcount, FAST_COUNT);
  else
    {
      if (fastsearch(needle, ndlen, &wildcard, 1, 1, FAST_SEARCH) == -1)
	return fastsearch(haystack, hslen, needle, ndlen, maxcount, FAST_COUNT);
      else
	return wfastsearch(haystack, hslen, needle, ndlen, wildcard, maxcount, FAST_COUNT);
    }
}
