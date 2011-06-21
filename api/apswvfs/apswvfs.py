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
    self.node = self.vfs.getnode(filename)
    self.vfile = self.node.open()

  def xRead(self, size, offset):
    self.vfile.seek(offset)
    return self.vfile.read(size)

  def xWrite(self):
    return 0

  def xClose(self):
    self.vfile.close()

  def xSectorSize(self):
    return 512

  def xDeviceCharacteristics(self):
    return 0 

  def xLock(self, level):
    pass

  def xUnlock(self, level):
    pass

  def xSync(self, flags):
    pass

  def xTruncate(self, newsize):
    pass
  
  def xFileSize(self):
    return self.vfile.node().size() 

  def xFileControl(self, op, ptr):
     return False 
