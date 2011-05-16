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

#ifndef __THREADING_HPP__
#define __THREADING_HPP__

#ifdef WIN32
  #define mutex_lock EnterCriticalSection
  #define mutex_unlock LeaveCriticalSection
  #define mutex_init(var)  CRITICAL_SECTION var;
#else
  #include <pthread.h>
  #define mutex_lock pthread_mutex_lock
  #define mutex_unlock pthread_mutex_unlock
  #define mutex_init(var) pthread_mutex_t var = PTHREAD_MUTEX_INITIALIZER;
#endif

#endif
