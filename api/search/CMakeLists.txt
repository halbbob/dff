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

find_library(TRE_LIBRARY NAMES tre PATH_SUFFIXES /usr /usr/local)
if (TRE_LIBRARY)
   add_definitions (-DHAVE_TRE)
   message(STATUS "tre library found: ${TRE_LIBRARY}, regexp and fuzzy match activated")
else (TRE_LIBRARY)
     #add_definitions (-DHAVE_TRE)
     message(STATUS "tre library not found, regexp and fuzzy match not activated")
endif (TRE_LIBRARY)



FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

#FIND_PACKAGE(PythonLibs)

INCLUDE_DIRECTORIES(${PYTHON_INCLUDE_PATH})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE_DIRECTORIES(../include)
INCLUDE_DIRECTORIES(/usr/include)
INCLUDE_DIRECTORIES(/usr/local/include)

SET_SOURCE_FILES_PROPERTIES(libsearch.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(libsearch python libsearch.i search.cpp boyer_moore.cpp)
if (TRE_LIBRARY)
   SWIG_LINK_LIBRARIES(libsearch ${PYTHON_LIBRARIES} ${TRE_LIBRARY})
else (TRE_LIBRARY)
   SWIG_LINK_LIBRARIES(libsearch ${PYTHON_LIBRARIES})
endif (TRE_LIBRARY)

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
  set_target_properties (${SWIG_MODULE_libsearch_REAL_NAME} PROPERTIES
  SUFFIX ".pyd"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

set(libsearch_srcs
  libsearch.py
  find.py
  __init__.py
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/__init__.py)

install_lib(${SWIG_MODULE_libsearch_REAL_NAME})
install_file(libsearch ${libsearch_srcs})
