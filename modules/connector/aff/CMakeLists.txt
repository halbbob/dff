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


FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

include_directories(${PYTHON_INCLUDE_PATH})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_HOME_DIRECTORY}/api/include)

set(aff_srcs
    aff.cpp
    affnode.cpp
)

SET_SOURCE_FILES_PROPERTIES(aff.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(AFF python aff.i ${aff_srcs})
if(WIN32)
  SWIG_LINK_LIBRARIES(AFF ${PYTHON_LIBRARIES} _libexceptions _libtypes _libvfs afflib libeay32 ssleay32 zlib Ws2_32)
else(WIN32)
  SWIG_LINK_LIBRARIES(AFF ${PYTHON_LIBRARIES} _libexceptions _libtypes _libvfs afflib)
endif(WIN32)

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_AFF_REAL_NAME} PROPERTIES
  SUFFIX ".pyd"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

if(WIN32)
  set(aff_files
    AFF.py
    afflib.dll
    zlib.dll
  )
else(WIN32)
  set(aff_files
    AFF.py
  )
endif(WIN32)

install_lib(${SWIG_MODULE_AFF_REAL_NAME})
install_file(aff ${aff_files})
