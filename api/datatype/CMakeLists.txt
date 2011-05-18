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
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
  SUFFIX ".pyd"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

set(datatype_srcs
  __init__.py
  magichandler.py
  libdatatype.py    
  )

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/__init__.py)
install_lib(${SWIG_MODULE_libdatatype_REAL_NAME})
install_file(datatype ${datatype_srcs})
