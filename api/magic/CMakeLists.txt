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
# 

FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

include_directories(${PYTHON_INCLUDE_PATH})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(../include)
	
set (magichandler_srcs
    magichandler.cpp
)

SET_SOURCE_FILES_PROPERTIES(libmagichandler.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(libmagichandler python libmagichandler.i magichandler.cpp)
SWIG_LINK_LIBRARIES(libmagichandler ${PYTHON_LIBRARIES} magic)

if(CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_libmagichandler_REAL_NAME} PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
  SUFFIX ".pyd")
  set(magichandler_srcs
	__init__.py
	libmagichandler.py
 	magic.mgc
 	magic1.dll
 	regex2.dll
	)
else (CMAKE_GENERATOR MATCHES "Visual Studio")
  set(magichandler_srcs
	__init__.py
	libmagichandler.py
	)
endif(CMAKE_GENERATOR MATCHES "Visual Studio")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/__init__.py)

install_lib(${SWIG_MODULE_libmagichandler_REAL_NAME})
install_file(magichandler ${magichandler_srcs})
