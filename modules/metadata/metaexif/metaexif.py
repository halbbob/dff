from api.module.script import Script 
from api.module.module import Module
from api.types.libtypes import Variant, VMap, Argument, typeId, vtime
from api.vfs.libvfs import AttributesHandler
import time

import EXIF 

# Mostly in the form 2009:12:14 14:47:11
dateTimeTags = [0x0132, 0x9003, 0x9004]

class EXIFHandler(AttributesHandler):
  def __init__(self):
    AttributesHandler.__init__(self, "exif")
    self.__disown__()
 
  def  attributes(self, node): #metaexif.status(decoding exif')
    attr = VMap()
    attr.thisown = False
    file = node.open()
    tags = EXIF.process_file(file)
    if len(tags) == 0:
      v = Variant("no exif")
      v.thisown = 0
      attr["info"] = v
      return attr
    else:
      sortedTags = {}
      for tag in tags.keys():
        if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
          spaceidx = tag.find(" ")
          ifd = tag[:spaceidx].strip()
          if ifd == "Image":
            ifd = "IFD 0 (Image)"
          if ifd == "Thumbnail":
            ifd = "IFD 1 (Thumbnail)"
          key = tag[spaceidx:].strip()
          val = None
          if tags[tag].tag in dateTimeTags:
            # Try converting from usual string format to vtime, or to string
            # if it fails.
            try:
              vt = time.strptime(str(tags[tag]), '%Y:%m:%d %H:%M:%S')
              val = vtime(vt.tm_year, vt.tm_mon, vt.tm_mday, vt.tm_hour, vt.tm_min, vt.tm_sec, 0)
              val.thisown = False
            except ValueError:
              pass
          if not val:
            try:
              val = str(tags[tag])
            except:
              val = "cannot be decoded"
          if ifd not in sortedTags.keys():
            sortedTags[ifd] = []
          sortedTags[ifd].append((key, val))
      for ifd in sortedTags.keys():
        m = VMap()
	m.thisown = 0 
        for res in sortedTags[ifd]:
	  v = Variant(res[1])
	  v.thisown = False
          m[res[0]]  = v
        vv = Variant(m)
        vv.thisown = False
        attr[ifd] = vv 
    return attr

class MetaEXIF(Script):
  def __init__(self):
   Script.__init__(self, "metaexif")
   self.handler = EXIFHandler() 

  def start(self, args):
    try:
      node = args['file'].value()
      self.stateinfo = "Registering node: " + str(node.name())
      node.registerAttributes(self.handler)
    except KeyError:
      pass

class metaexif(Module): 
  """This modules generate exif metadata in node attributes"""
  def __init__(self):
    Module.__init__(self, "metaexif", MetaEXIF)
    self.conf.addArgument({"name": "file",
                           "description": "file for extracting metadata",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["jpeg", "TIFF"]})
    self.flags = "single"
    self.tags = "Metadata"
