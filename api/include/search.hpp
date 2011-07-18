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
#include <vector>
#include "export.hpp"

#include "fastsearch.hpp"
#ifdef HAVE_TRE
#include "tre/tre.h"
#endif

class FastSearch
{
public:
  EXPORT FastSearch();
  EXPORT virtual ~FastSearch();
  EXPORT virtual int32_t	find(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard='\0');
  EXPORT virtual int32_t	rfind(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard='\0');
  EXPORT virtual int32_t       count(unsigned char* haystack, uint32_t hslen, unsigned char* needle, uint32_t ndlen, unsigned char wildcard='\0', int32_t maxcount=-1);
};


class Search
{
public:
  enum PatternSyntax
    {
      Fixed = 0,
      Wildcard = 1,
      Regexp = 2,
      Fuzzy = 3
    };
  enum CaseSensitivity
    {
      CaseInsensitive = 0,
      CaseSensitive = 1
    };
  Search();
  Search(std::string pattern, CaseSensitivity cs = CaseSensitive, PatternSyntax syntax = Fixed);
  ~Search();
  uint32_t		needleLength();
  void			setPattern(std::string pattern);
  std::string		pattern();
  void			setPatternSyntax(PatternSyntax syntax);
  PatternSyntax		patternSyntax();
  void			setCaseSensitivity(CaseSensitivity cs);
  CaseSensitivity	caseSensitivity();
  //void			setFuzzyWeight();
  int32_t		find(char* haystack, uint32_t hslen) throw (std::string);
  int32_t		find(std::string haystack) throw (std::string);
  int32_t		rfind(char* haystack, uint32_t hslen) throw (std::string);
  int32_t		rfind(std::string haystack) throw (std::string);
  int32_t		count(char* haystack, uint32_t hslen, int32_t maxcount=-1) throw (std::string);
  int32_t		count(std::string haystack, int32_t maxcount=-1) throw (std::string);
  // std::vector<uint32_t>	indexes(char* haystack, uint32_t hslen) throw (std::string);
  // std::vector<uint32_t>	indexes(std::string haystack) throw (std::string);
private:
#ifdef HAVE_TRE
  regex_t			__preg;
  regaparams_t			__aparams;
#endif
  std::vector<std::string*>	__wctxs;
  std::string			__pattern;
  CaseSensitivity		__cs;
  PatternSyntax			__syntax;
  bool				__compiled;
  bool				__needtrefree;
  uint32_t			__nlen;
  void				__compile() throw (std::string);

  //find methods implementation
  int32_t			__ffind(char* haystack, uint32_t hslen);
  int32_t			__wfind(char* haystack, uint32_t hslen);
  int32_t			__refind(char* haystack, uint32_t hslen);
  int32_t			__afind(char* haystack, uint32_t hslen);

  //rfind methods implementation
  int32_t			__frfind(char* haystack, uint32_t hslen);
  int32_t			__wrfind(char* haystack, uint32_t hslen);
  
  //count methods implementation
  int32_t			__fcount(char* haystack, uint32_t hslen, int32_t maxcount);
  int32_t			__wcount(char* haystack, uint32_t hslen, int32_t maxcount);
  int32_t			__recount(char* haystack, uint32_t hslen, int32_t maxcount);
  int32_t			__acount(char* haystack, uint32_t hslen, int32_t maxcount);
};

#endif
