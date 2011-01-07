/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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

#ifndef __BOOT_CODE_H__
#define __BOOT_CODE_H__

#ifndef WIN32
#include <stdint.h>
#else
#include "wstdint.h"
#endif
class	BootCode
{
  /*! \brief Boot code
  */

public:
  BootCode();
  ~BootCode();

  const	uint8_t* getBootCode() const
  {
    return _boot_code;
  }

private:
  uint8_t	_boot_code[1024];
};

#endif
