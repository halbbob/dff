# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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
#  Solal Jacob <sja@digital-forensic.org>

add_subdirectory(devices)

add_subdirectory (local)
IF (EWF_FOUND)
   add_subdirectory (ewf)
ENDIF (EWF_FOUND)

if (AFF_FOUND)
   add_subdirectory(aff)
else (AFF_FOUND)
    message(STATUS "AFF library not found. Connector module will not be built.")
endif(AFF_FOUND)

if(HAVE_FUSE)
  add_subdirectory (fuse)
endif(HAVE_FUSE)

set(connector_files
   __init__.py
)

install_file(connector ${connector_files})
