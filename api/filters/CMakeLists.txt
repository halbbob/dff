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

find_package(BISON)
find_package(FLEX)

#FIND_PACKAGE(PythonLibs)

INCLUDE_DIRECTORIES(${PYTHON_INCLUDE_PATH})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE_DIRECTORIES(../include)

BISON_TARGET(parser parser.y ${CMAKE_CURRENT_SOURCE_DIR}/parser.cpp)
FLEX_TARGET(lexer lexer.l ${CMAKE_CURRENT_SOURCE_DIR}/lexer.cpp  COMPILE_FLAGS "--header-file=lexer.hpp")

# does not seem to be mandatory. Here just in case and as a reminder...
#ADD_FLEX_BISON_DEPENDENCY(lexer parser)

SET_SOURCE_FILES_PROPERTIES(libfilters.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(libfilters python libfilters.i filter.cpp astnodes.cpp ${BISON_parser_OUTPUTS} ${FLEX_lexer_OUTPUTS})

SWIG_LINK_LIBRARIES(libfilters ${PYTHON_LIBRARIES} _libevents _libvfs _libtypes _libsearch)

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
  set_target_properties (${SWIG_MODULE_libfilters_REAL_NAME} PROPERTIES
  SUFFIX ".pyd"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

set(libfilters_srcs
  libfilters.py
  __init__.py
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/__init__.py)

install_lib(${SWIG_MODULE_libfilters_REAL_NAME})
install_file(libfilters ${libfilters_srcs})
