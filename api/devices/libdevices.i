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

%module(package="api.devices") libdevices

%feature("director") Device;
%feature("director") DeviceList;


%include "std_string.i"
%include "std_vector.i"
%include "windows.i"
#ifndef WIN32
%include "stdint.i"
#else
%include "wstdint.i"
#endif

%include <python/cwstring.i>

%apply wchar_t       * {WCHAR *}
%apply wchar_t const * {WCHAR const *}
%apply const wchar_t * {const WCHAR *}


%{
#include "../include/export.hpp"
#ifdef WIN32
#include "../include/wmidev.hpp"
#endif
#include "../include/device.hpp"
%}
#ifdef WIN32
%include "../include/wmidev.hpp"
#endif
%include "../include/device.hpp"

namespace std
{
  %template(devList) vector<Device *>;
}

#ifdef WIN32
%extend WMIDevices
{
%pythoncode
%{
def __iter__(self):
  for dev in self.deviceList:
        yield dev

def __len__(self):
  return len(self.deviceList)

def __getitem__(self, c):
  return self.deviceList[c]
%}

};
#endif

%extend DeviceList
{
%pythoncode
%{
def __iter__(self):
  for dev in self.deviceList:
        yield dev

def __len__(self):
  return len(self.deviceList)

def __getitem__(self, c):
  return self.deviceList[c]
%}

};
