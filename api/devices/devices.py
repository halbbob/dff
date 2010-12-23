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
