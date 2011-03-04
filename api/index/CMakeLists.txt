# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2010 ArxSys
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
INCLUDE_DIRECTORIES(${QT_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${QT_QTCORE_INCLUDE_DIR})
#INCLUDE_DIRECTORIES(../include)
#INCLUDE_DIRECTORIES(./includes)
#INCLUDE_DIRECTORIES(.)
#INCLUDE_DIRECTORIES(./CLucene)

#${CLUCENE_LIBRARIES}

SET_SOURCE_FILES_PROPERTIES(libindex.i PROPERTIES CPLUSPLUS ON)
if (HAVE_64_BIT)
   SET(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} -D64_BITS)
endif (HAVE_64_BIT)

SWIG_ADD_MODULE(libindex python libindex.i index.cpp index_search.cpp)
MESSAGE(${PYTHON_LIBRARIES})
if (UNIX)
   SWIG_LINK_LIBRARIES(libindex ${PYTHON_LIBRARIES} ${QT_QTCORE_LIBRARIES} clucene _libvfs)
else (UNIX)
  SWIG_LINK_LIBRARIES(libindex ${PYTHON_LIBRARIES} ${QT_QTCORE_LIBRARIES} clucene _libvfs)
endif (UNIX)
if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_libindex_REAL_NAME} PROPERTIES
  PREFIX "../"
  SUFFIX ".pyd"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

set(index_srcs
  __init__.py
  libindex.py
)

install_lib(${SWIG_MODULE_libindex_REAL_NAME})
install_file(index ${index_srcs})
