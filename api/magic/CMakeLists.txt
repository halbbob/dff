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
# 
# Compile magic Python bindings for Windows. Libraries like regex2.dll,
# zlib1.dll, magic1.dll and magic1.lib are already compiled and versionned
# as it.
# 

if(WIN32 AND NOT UNIX)
  add_custom_target(magic1.lib ALL
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
	${CMAKE_CURRENT_SOURCE_DIR}/magic1.lib ${CMAKE_CURRENT_BINARY_DIR}/magic1.lib
	)

  include_directories(${PYTHON_INCLUDE_PATH})
  include_directories(${CMAKE_CURRENT_SOURCE_DIR})
  add_library(magic SHARED py_magic.c)
  target_link_libraries(magic magic1 ${PYTHON_LIBRARIES})
  add_dependencies(magic magic1.lib)
	
  if(CMAKE_GENERATOR MATCHES "Visual Studio")
	set_target_properties (magic PROPERTIES
	SUFFIX ".pyd"
	RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
  	RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
  	RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
	)
  endif(CMAKE_GENERATOR MATCHES "Visual Studio")

  set(magic_srcs
    __init__.py
    magic.mgc
    magic1.dll
    magic.pyd
    zlib1.dll
    regex2.dll
    )
	
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/__init__.py)

else(WIN32 AND NOT UNIX)

  set(magic_srcs
    magic.mgc
    )

endif(WIN32 AND NOT UNIX)

install_file(magic ${magic_srcs})
