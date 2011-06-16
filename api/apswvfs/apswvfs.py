from api.vfs.vfs import vfs
import apsw

class apswVFS(apsw.VFS):
  def __init__(self, vfsname="dff-vfs", basevfs=""):
    self.vfsname = vfsname
    self.basevfs = basevfs
    apsw.VFS.__init__(self, self.vfsname, self.basevfs)

  def xOpen(self, name, flags):
    return apswVFile(self.basevfs, name, flags)


class apswVFile(apsw.VFSFile):
  def __init__(self, inheritfromvfsname, filename, flags):
    self.vfs = vfs()
    #apsw.VFSFile.__init__(self, inheritfromvfsname, filename, flags)
    print "inheritfromvfsname " + str(inheritfromvfsname)
    print "filename " + str(filename)
    print "flags " + str(flags)
    self.node = self.vfs.getnode(filename)
    self.vfile = self.node.open()

  def xRead(self, size, offset):
    self.vfile.seek(offset)
    return self.vfile.read(size)

  def xWrite(self):
    print "This file is read only"
    return 0
