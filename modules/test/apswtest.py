__dff_module_testapsw_version__ = "1.0.0"

from struct import unpack

from api.vfs import *
from api.module.module import *
from api.types.libtypes import Variant, VList, VMap, Argument, Parameter, typeId
from api.vfs.libvfs import *
from api.apswvfs import apswvfs
import apsw

class ApswTest(Script):
    def __init__(self):
        Script.__init__(self, "ApswTest")
        self.name = "ApswTest"

    def start(self, args):     
       self.node = args["node"].value()
       print "analyzing db: " + str(self.node.absolute())
       avfs = apswvfs.apswVFS()
       db = apsw.Connection(self.node.absolute(), vfs = avfs.vfsname)	
       c = db.cursor()
       c.execute("SELECT * FROM sqlite_master WHERE type='table'")
       for row in c:
  	 print row 
      

class apswtest(Module):
    def __init__(self):
        Module.__init__(self, "apswtest", ApswTest) 
        self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Node,
                               "name": "node",
                               "description": "sqlite base."
                               })
        self.tags = "test"
