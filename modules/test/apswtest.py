__dff_module_testapsw_version__ = "1.0.0"

from struct import unpack

from api.vfs import *
from api.module.module import *
from api.types.libtypes import Variant, VList, VMap, Argument, Parameter, typeId
from api.vfs.libvfs import *
from api.apswvfs import apswvfs
import apsw

class ApswTest(mfso):
    def __init__(self):
        mfso.__init__(self, "browser_forensics")
        self.name = "browser_forensics"
        self.__disown__()

    def start(self, args):     
       node = args["node"].value() 
       print "analyzing db:"
       print node.absolute()
       avfs = apswvfs.apswVFS()
       print apsw.vfsnames()	
       db = apsw.Connection(node.absolute(), vfs = avfs.vfsname)	

class apswtest(Module):
    def __init__(self):
        Module.__init__(self, "apswtest", ApswTest) 
        self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Node,
                               "name": "node",
                               "description": "sqlite base."
                               })
        self.tags = "test"
