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
#  Frederic Baguelin <fba@digital-forensic.org>


FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

#FIND_PACKAGE(PythonLibs)

INCLUDE_DIRECTORIES(${PYTHON_INCLUDE_PATH})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE_DIRECTORIES(../include)

SET_SOURCE_FILES_PROPERTIES(libvariant.i PROPERTIES CPLUSPLUS ON)
set(CMAKE_SWIG_FLAGS -threads -fvirtual -fastdispatch)
IF (WIN32)
  set(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} -DWIN32)
ENDIF(WIN32)
SWIG_ADD_MODULE(libvariant python libvariant.i variant.cpp)
SWIG_LINK_LIBRARIES(libvariant ${PYTHON_LIBRARIES} _libtype)
if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_libvariant_REAL_NAME} PROPERTIES
  PREFIX "../"
  SUFFIX ".pyd"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")
set(variant_srcs
  __init__.py
  libvariant.py
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/__init__.py)

install_file(variant ${variant_srcs})
install_lib(${SWIG_MODULE_libvariant_REAL_NAME})
