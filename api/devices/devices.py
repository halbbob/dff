try :
  import dbus
  import gobject
except ImportError:
	pass
#from dbushal import DBusHal


class Devices():
  def __init__(self):
    self.devices = DBusHal()

  def __len__(self):
     return len(self.devices)	

  def __iter__(self):
     for dev in self.devices():
	yield dev  

  def __getitem__(self, c):
     return self.devices[c]

class DevicesList():
  def __init__(self):
    self.storageDevices = [] 

  def __iter__(self):
     for dev in self.storageDevices:
	yield dev

  def __len__(self):
     return len(self.storageDevices)   

  def __getitem__(self, c):
     return self.storageDevices[c]

class StorageDevice():
  def __init__(self, uid, proxy_dev):
    self.uid = uid
    self.ddev = proxy_dev
    
  def getAllProperties(self):
    return dev_obj.GetAllProperties()

  def allProperties(self):
     buff = self.uid + "\n"
     for key, val in self.ddev.GetAllProperties().iteritems():
        buff += str(key)  + " : " + str(val) + "\n"
     return buff

  def blockDevice(self):
   return str(self.ddev.GetProperty('block.device'))

  def serialNumber(self):
   try:
     return str(self.ddev.GetProperty('storage.serial'))
   except dbus.exceptions.DBusException:
      return "Not found"

  def model(self):
    try:
      return str(self.ddev.GetProperty('storage.model'))
    except dbus.exceptions.DBusException:
      return "Not found"
	
  def size(self):
   if int(self.ddev.GetProperty('storage.removable')) == 1:
    try:
     return long(self.ddev.GetProperty('storage.removable.media_size'))	
    except dbus.exceptions.DBusException:
	return 0
   else:
     return long(self.ddev.GetProperty('storage.size'))
  

  ##def blockMajor(self):
   #return self.ddev.GetProperty('block.major') 
#
  #def blockMinor(self):
    #return self.ddev.GetProperty('block.minor')
#
  #def isVolume(self):
    #return self.ddev.GetProperty('block.is_volume')
#
  #def noPartitions(self):
    #return self.ddev.GetProperty('block.no_partitions')
 # 
  #def haveScanned(self):
    #return self.ddev.GetProperty('block.have_scanned')

  def __str__(self):
   buff = ""
   buff += "Device uid      : " + str(self.uid) + "\n"
   buff += "Block device    : " + str(self.blockDevice()) + "\n"
   #buff += "Block no partitions :" + str(self.noPartitions()) + "\n"
   #buff += "Block have scanned :" + str(self.haveScanned()) + "\n"
   return buff


class DBusHal(DevicesList):
  """This class try to initialize devices list through dbus-HAL"""
  def __init__(self):
    DevicesList.__init__(self)
    system_bus = dbus.SystemBus()
    bus_name = "org.freedesktop.Hal" 
    object = "/org/freedesktop/Hal/Manager"
    miface = "org.freedesktop.Hal.Manager"
    proxy = system_bus.get_object(bus_name, object)
    iface = dbus.Interface(proxy, miface)
    devices_uid = iface.FindDeviceByCapability('block')
    for dev_uid in  devices_uid:
      dev_obj = system_bus.get_object('org.freedesktop.Hal', dev_uid)
      dev_obj = dbus.Interface(dev_obj, 'org.freedesktop.Hal.Device')
      if dev_obj.GetProperty('info.category') == "storage":	
        self.storageDevices.append(StorageDevice(dev_uid, dev_obj))

  def __str__(self):
    buff = ""
    for dev in self.storageDevices:
	buff += dev.allProperties()
	buff += "\n"
    return buff
