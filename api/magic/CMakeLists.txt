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
#  Christophe Malinge <cma@digital-forensic.org>
#  Frederic Baguelin <fba@digital-forensic.org>
#  Solal Jacob <sja@digital-forensic.org>

if (UNIX AND NOT WIN32)
  set(magic_srcs
    __init__.py
    filetype.py
    )
endif(UNIX AND NOT WIN32)

if(WIN32 AND NOT UNIX)
  include_directories(${PYTHON_INCLUDE_PATH})
  include_directories(${CMAKE_CURRENT_SOURCE_DIR})
  add_library (magic SHARED py_magic.c)
  target_link_libraries (magic magic1 ${PYTHON_LIBRARIES})

  if (CMAKE_GENERATOR MATCHES "Visual Studio")
	set_target_properties (magic PROPERTIES
	PREFIX "../"
	SUFFIX ".pyd"
	)
  endif ( CMAKE_GENERATOR MATCHES "Visual Studio")
  
  set(magic_srcs
    __init__.py
    magic.mgc
    filetype.py
    magic1.dll
    magic.pyd
    zlib1.dll
    regex2.dll
    )
endif(WIN32 AND NOT UNIX)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/__init__.py)

install_file(magic ${magic_srcs})
