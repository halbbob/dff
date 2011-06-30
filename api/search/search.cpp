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

#include <iostream>
#include <string.h>

Search::Search()
{
  this->__pattern = "";
  this->__compiled = false;
  this->__needtrefree = false;
  this->__cs = CaseSensitive;
  this->__syntax = Fixed;
}

Search::Search(std::string pattern, CaseSensitivity cs, PatternSyntax syntax)
{
  this->__pattern = pattern;
  this->__cs = cs;
  this->__syntax = syntax;
}

Search::~Search()
{
#if HAVE_TRE
  if (this->__needtrefree)
    tre_regfree(&this->__preg);
#endif
}

void			Search::setPattern(std::string pattern)
{
  if (this->__pattern != pattern)
    this->__compiled = false;
  this->__pattern = pattern;
}
 
std::string		Search::pattern()
{
  return this->__pattern;
}

void			Search::setPatternSyntax(Search::PatternSyntax syntax)
{
#ifndef HAVE_TRE
  if ((syntax == Regexp) || (syntax == Fuzzy))
    std::cout << "not compiled with tre library, search won't provide results" << std::endl;
#endif
  if (this->__syntax != syntax)
    this->__compiled = false;
  this->__syntax = syntax;
}

Search::PatternSyntax	Search::patternSyntax()
{
  return this->__syntax;
}

void			Search::setCaseSensitivity(Search::CaseSensitivity cs)
{
  this->__cs = cs;
}

Search::CaseSensitivity	Search::caseSensitivity()
{
  return this->__cs;
}

  //void			setFuzzyWeight();
int32_t			Search::find(char* haystack, uint32_t hslen) throw (std::string)
{
  if (!this->__compiled)
    {
      try
	{
	  this->__compile();
	}
      catch (std::string err)
	{
	  throw (err);
	}
    }
  switch (this->__syntax)
    {
    case Fixed:
      return 0;
    case Wildcard:
      return 0;
    case Regexp:
#ifdef HAVE_TRE
      return this->__refind(haystack, hslen);
#else
      throw std::string("regexp support not activated (libtre not linked)");
#endif
    case Fuzzy:
#ifdef HAVE_TRE
      return this->__afind(haystack, hslen);
#else
      throw std::string("fuzzy support not activated (libtre not linked)");
#endif
    default:
      throw std::string("syntax is neither setted nor correct");
    }  
  return 0;
}

int32_t			Search::find(std::string haystack) throw (std::string)
{
  try
    {
      return this->find((char*)haystack.c_str(), haystack.size());
    }
  catch (std::string err)
    {
      throw (err);
    }
}

int32_t			Search::rfind(char* haystack, uint32_t hslen) throw (std::string)
{
  if (!this->__compiled)
    {
      try
	{
	  this->__compile();
	}
      catch (std::string err)
	{
	  throw (err);
	}
    }
  if (this->__syntax == Regexp || this->__syntax == Fuzzy)
    throw std::string("regexp support not activated (libtre not linked)");
  else if (this->__syntax == Wildcard)
    this->__wrfind(haystack, hslen);
  else if (this->__syntax == Fixed)
    this->__frfind(haystack, hslen);
}

int32_t			Search::rfind(std::string haystack) throw (std::string)
{
  try
    {
      this->rfind((char*)haystack.c_str(), haystack.size());
    }
  catch (std::string err)
    {
      throw (err);
    }
}

int32_t			Search::count(char* haystack, uint32_t hslen, int32_t maxcount) throw (std::string)
{
  if (!this->__compiled)
    {
      try
	{
	  this->__compile();
	}
      catch (std::string err)
	{
	  throw (err);
	}
    }
}

int32_t			Search::count(std::string haystack, int32_t maxcount) throw (std::string)
{
  try
    {
      this->count((char*)haystack.c_str(), haystack.size());
    }
  catch (std::string err)
    {
      throw (err);
    }
}

std::vector<uint32_t>	Search::indexes(char* haystack, uint32_t hslen) throw (std::string)
{
  if (!this->__compiled)
    {
      try
	{
	  this->__compile();
	}
      catch (std::string err)
	{
	  throw (err);
	}
    }
}

std::vector<uint32_t>	Search::indexes(std::string haystack) throw (std::string)
{
  try
    {
      this->indexes((char*)haystack.c_str(), haystack.size());
    }
  catch (std::string err)
    {
      throw (err);
    }
}


void			Search::__compile() throw (std::string)
{
  int	cflags = REG_EXTENDED;

  switch (this->__syntax)
    {
    case Fixed:
      return;
    case Wildcard:
      return;

    case Regexp:
#ifdef HAVE_TRE
      if (this->__needtrefree)
	tre_regfree(&this->__preg);      
      if (this->__cs == Search::CaseInsensitive)
	cflags |= REG_ICASE;
      tre_regcomp(&this->__preg, this->__pattern.c_str(), cflags);
      this->__needtrefree = true;
      return;
#else
      throw std::string("regexp support not activated (libtre not linked)");
#endif

    case Fuzzy:
#ifdef HAVE_TRE
      if (this->__needtrefree)
	tre_regfree(&this->__preg);
      cflags = REG_LITERAL;
      if (this->__cs == Search::CaseInsensitive)
	cflags |= REG_ICASE;
      tre_regcomp(&this->__preg, this->__pattern.c_str(), cflags);
      this->__needtrefree = true;
      return;
#else
      throw std::string("fuzzy support not activated (libtre not linked)");
#endif

    default:
      throw std::string("syntax is neither setted nor correct");
    }
  this->__compiled = true;
}


int32_t			Search::__refind(char* haystack, uint32_t hslen)
{
  int32_t	ret;

  ret = -1;
#ifdef HAVE_TRE
  regmatch_t	pmatch[1];

  if (tre_regnexec(&this->__preg, haystack, hslen, 1, pmatch, 0) == REG_OK)
    ret = pmatch[0].rm_so;
#endif
  return ret;
}

int32_t			Search::__afind(char* haystack, uint32_t hslen)
{
  int32_t	ret;

  ret = -1;
#ifdef HAVE_TRE
  regaparams_t	params;
  regamatch_t	match;
  regmatch_t	pmatch[1];

  params.max_err = 3;
  memset(&match, 0, sizeof(match));
  match.pmatch = pmatch;
  match.nmatch = 1;
  if (tre_reganexec(&this->__preg, haystack, hslen, &match, params, 0) == REG_OK)
    ret = match.pmatch[0].rm_so;
#endif
  return ret;
}


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
