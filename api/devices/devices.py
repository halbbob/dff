# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.
#  
# See http://www.digital-forensic.org for more information about this
# project. Please do not directly contact any of the maintainers of
# DFF for assistance; the project provides a web site, mailing lists
# and IRC channels for your use.
# 
# Author(s):
#  Solal Jacob <sja@digital-forensic.org>
# 

import os
from api.devices.libdevices import Device, DeviceList

if os.name == "posix":
  try :
    from dbushaldev import DBusHalDevices
  except ImportError:
    pass
else:
  try :
    from api.devices.libdevices import WMIDevices
  except ImportError:
    pass

class Devices():
  def __init__(self):
    if os.name == "posix":
       self.__instance = DBusHalDevices()
    else :
       self.__instance = WMIDevices()	       

  def __getattr__(self, attr):
        return getattr(self.__instance, attr)
