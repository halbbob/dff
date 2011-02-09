from api.module.script import Script 
from api.module.module import Module
from api.variant.libvariant import Variant, VMap
from api.vfs.libvfs import AttributesHandler

import EXIF 

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
    node = args.get_node('file')
    self.stateinfo = "registering" + node.name()
    node.registerAttributes(self.handler)

class metaexif(Module): 
  """This modules generate exif metadata in node attributes"""
  def __init__(self):
    Module.__init__(self, "metaexif", MetaEXIF)
    self.conf.add("file", "node", False, "File to decode.")
    self.conf.add_const("mime-type", "jpeg")
    self.conf.add_const("mime-type", "TIFF")
    self.flags = "single"
    self.tags = "Metadata"
