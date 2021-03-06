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
#  Jeremy MOUNIER <jmo@digital-forensic.org>


FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

include_directories(${PYTHON_INCLUDE_PATH})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_HOME_DIRECTORY}/api/include)


set(vmware_srcs
  vmware.cpp
  diskDescriptor.cpp
  extent.cpp
  link.cpp
  vmnode.cpp
)

SET_SOURCE_FILES_PROPERTIES(vmware.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(VMWARE python vmware.i ${vmware_srcs})
SWIG_LINK_LIBRARIES(VMWARE ${PYTHON_LIBRARIES} _libexceptions _libtypes _libvfs)

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_VMWARE_REAL_NAME} PROPERTIES
  SUFFIX ".pyd"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

set(vmware_files
  VMWARE.py
)

install_lib(${SWIG_MODULE_VMWARE_REAL_NAME})
install_file(vmware ${vmware_files})
