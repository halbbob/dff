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

FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

INCLUDE_DIRECTORIES(${PYTHON_INCLUDE_PATH})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE_DIRECTORIES(../include)

SET_SOURCE_FILES_PROPERTIES(libdatatype.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(libdatatype python libdatatype.i datatype.cpp) 
SWIG_LINK_LIBRARIES(libdatatype ${PYTHON_LIBRARIES} _libtypes )
if (CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_libdatatype_REAL_NAME} PROPERTIES
  PREFIX "../"
  SUFFIX ".pyd"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")
if (UNIX AND NOT WIN32)
  set(datatype_srcs
    __init__.py
    magichandler.py
    libdatatype.py    
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
    magichandler.py
    magic1.dll
    magic.pyd
    zlib1.dll
    regex2.dll
    libdatatype.py
    )
endif(WIN32 AND NOT UNIX)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/__init__.py)
install_lib(${SWIG_MODULE_libdatatype_REAL_NAME})
install_file(datatype ${datatype_srcs})
