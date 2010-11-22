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


FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

#FIND_PACKAGE(PythonLibs)

INCLUDE_DIRECTORIES(${PYTHON_INCLUDE_PATH})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE_DIRECTORIES(../include)

SET_SOURCE_FILES_PROPERTIES(libtree.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(libtree python libtree.i TwoThreeTree.cpp TwoThreeNode.cpp)
SWIG_LINK_LIBRARIES(libtree ${PYTHON_LIBRARIES})

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_libtree_REAL_NAME} PROPERTIES
  PREFIX "../"
  SUFFIX ".pyd"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")
set(tree_srcs
  libtree.py
  __init__.py
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/__init__.py)

install_lib(${SWIG_MODULE_libtree_REAL_NAME})
install_file(tree ${tree_srcs})
