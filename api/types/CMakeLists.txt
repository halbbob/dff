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
#  Solal Jacob <sja@digital-forensic.org>


FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

#FIND_PACKAGE(PythonLibs)

INCLUDE_DIRECTORIES(${PYTHON_INCLUDE_PATH})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE_DIRECTORIES(../include)


add_definitions(-D__STDC_LIMIT_MACROS)
SET_SOURCE_FILES_PROPERTIES(libtypes.i PROPERTIES CPLUSPLUS ON)	
set(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} -threads -fvirtual -fastdispatch)
IF (WIN32)
  set(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} -DWIN32)	
ENDIF(WIN32)
SWIG_ADD_MODULE(libtypes python libtypes.i constant.cpp argument.cpp config.cpp path.cpp vtime.cpp variant.cpp confmanager.cpp)
SWIG_LINK_LIBRARIES(libtypes ${PYTHON_LIBRARIES})
if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_libtypes_REAL_NAME} PROPERTIES
  PREFIX "../"
  SUFFIX ".pyd"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")
set(type_srcs
  __init__.py
  libtypes.py
  OS.py
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/__init__.py)

install_file(type ${type_srcs})
install_lib(${SWIG_MODULE_libtypes_REAL_NAME})
