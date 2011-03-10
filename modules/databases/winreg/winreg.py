# DFF -- An Open Source Digital Forensics Framework
#
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
#  Jeremy MOUNIER < sja@arxsys.fr>
#

#from struct import unpack

from modules.databases.winreg.parseHives import *

from api.vfs import *
from api.module.module import *
from api.types.libtypes import Argument, typeId
from api.vfs.libvfs import *


class WINREG(mfso):
    def __init__(self):
        mfso.__init__(self, "winreg")
        self.name = "winreg"
        self.__disown__()

    def start(self, args):
       self.hive = args['file'].value()

       if self.hive.size() > 0:
           phive = parseHive(self.hive, self)

class winreg(Module):
  """This modules permit to virtualy reconstruct windows registry hives files on the VFS."""
  def __init__(self):
    Module.__init__(self, "winreg", WINREG)
    self.conf.addArgument({"name": "file",
                           "description": "Registry hive file",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["registry file"]})
    self.tags = "Databases"
