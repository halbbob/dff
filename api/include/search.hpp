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

#ifndef __SEARCH_HPP__
#define __SEARCH_HPP__

#ifndef WIN32
#include <stdint.h>
#else
#include "wstdint.h"
#endif
#include <string>
#include <list>
#include "export.hpp"

#include "fastsearch.hpp"

class BaseSearch
{
public:
  virtual ~BaseSearch() {}
  virtual int32_t	find(unsigned char* needle, uint32_t ndlen, uint32_t offset) = 0;
  virtual int32_t	rfind(unsigned char* needle, uint32_t ndlen, uint32_t offset) = 0;
  virtual bool		contains(unsigned char* needle, uint32_t ndlen, uint32_t offset) = 0;  
};

// class WildcardSearch: BaseSearch
// {
// public:
  
//   virtual int32_t	find(unsigned char* needle, uint32_t ndlen, unsigned char wildcard, uint32_t offset) = 0;
//   virtual int32_t	rfind(unsigned char* needle, uint32_t ndlen, unsigned char wildcard, uint32_t offset) = 0;
//   virtual bool		contains(unsigned char* needle, uint32_t ndlen, unsigned char wildcard, uint32_t offset) = 0;  
// };

// class SearchAlgorithm
// {
// public:
//   EXPORT			SearchAlgorithm() {}
//   EXPORT virtual		~SearchAlgorithm() {}
//   EXPORT virtual int32_t	find(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen) = 0;
//   //virtual int32_t	find(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard) = 0;
//   EXPORT virtual int32_t	rfind(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen) = 0;
//   //virtual int32_t	rfind(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard) = 0;
//   EXPORT virtual int32_t       count(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen) = 0;
//   // virtual int32_t       count(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard) = 0;
// };

class FastSearch//: public SearchAlgorithm
{
public:
  EXPORT FastSearch();
  EXPORT virtual ~FastSearch();
  EXPORT virtual int32_t	find(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard='\0');
  EXPORT virtual int32_t	rfind(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard='\0');
  EXPORT virtual int32_t       count(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard='\0', int32_t maxcount=-1);
};

// class SteppedSearch: public SearchAlgorithm
// {
// private:
//   uint32_t	__step;
// public:
//   SteppedSearch(uint32_t step);
//   ~SteppedSearch();
//   void		setStep(uint32_t step);
//   uint32_t	step();
// };

#endif
