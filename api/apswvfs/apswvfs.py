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
    print "aspwVFile open FINISH"

  def xRead(self, size, offset):
    print "APSW reading on the file"
    self.vfile.seek(offset)
    return self.vfile.read(size)

  def xWrite(self):
    print "APSW This file is read only"
    return 0

  def xClose(self):
    print "APSW closing file"
    self.vfile.close()

  def xSectorSize(self):
    #hohoho pas tres forensic tous cam etonnant pour SQL 
    print "APSW sector size"
    return 512

  def xDeviceCharacteristics(self):
    print "APSW device characteristics"
    #we have no caps
    return 0 

  def xLock(self, level):
    print "APSW xlock "
    #we are read only .... on lock by GIL 

  def xUnlock(self, level):
    print "APSW unlock"
    #ask GIL what he think about that...

  def xSync(self, flags):
    print "APSW sync"
    #read onlyyyyyyy

  def xTruncate(self, newsize):
    print "APSW truncate"
    #we are reeeead only 
  
  def xFileSize(self):
    print "APSW file size"
    return self.vfile.node.size() 

  def xFileControl(self, op, ptr):
     print "APSW Xfile control WTF ? "
     return False 
