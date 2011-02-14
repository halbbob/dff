from api.module.module import *
from api.types.libtypes import Argument, typeId

class EXTFS(Module):
  """ This module parses extented file system and try to recover deleted data."""
  def __init__(self):

    Module.__init__(self, 'extfs', Extfs)
    self.conf.addArgument({"name": "file",
                           "description": "file containing an EXT file system",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "ils",
                           "description": "List inodes",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "blk",
                           "description": "Block allocation status",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "fsstat",
                           "description": "File system statistic",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "istat",
                           "description": "Inode statistics",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "jstat",
                           "description": "journal statistics",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "SB_check",
                           "description": "check superblock validity",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "i_orphans",
                           "description": "Parse orphan inodes",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "root_inode",
                           "description": "Root inode number"
                           "input": Argument.Optional|Argument.Single|typeId.UInt64,
                           "parameters": {"type": Parameter.Editable,
                                          "predefined": [2]}
                           })
    self.conf.addArgument({"name": "SB_addr",
                           "description": "Super block address specified manualy",
                           "input": Argument.Optional|Argument.Single|typeId.UInt64,
                           "parameters": {"type": Parameter.Editable,
                                          "predefined": [1024]}
                           })
    #self.conf.add_const("mime-type", "ext2")
    #self.conf.add_const("mime-type", "ext3")
    #self.conf.add_const("mime-type", "ext4")
