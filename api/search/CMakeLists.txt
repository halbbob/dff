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

#FIND_PACKAGE(SWIG REQUIRED)
#INCLUDE(${SWIG_USE_FILE})

#FIND_PACKAGE(PythonLibs)

INCLUDE_DIRECTORIES(${PYTHON_INCLUDE_PATH})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE_DIRECTORIES(../include)

SET_SOURCE_FILES_PROPERTIES(libsearch.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(libsearch python libsearch.i search.cpp boyer_moore.cpp)
if (TRE_FOUND)
	if(WIN32)
		FILE(COPY ${TRE_DYN_LIBRARIES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
	endif(WIN32)
	SWIG_LINK_LIBRARIES(libsearch ${PYTHON_LIBRARIES} ${TRE_LIBRARY})
else (TRE_FOUND)
	SWIG_LINK_LIBRARIES(libsearch ${PYTHON_LIBRARIES})
endif (TRE_FOUND)

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
  set_target_properties (${SWIG_MODULE_libsearch_REAL_NAME} PROPERTIES
  SUFFIX ".pyd"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

if ( WIN32 )
	set(libsearch_srcs
		libsearch.py
		find.py
		__init__.py
		tre4.dll
		libiconv2.dll
		libintl3.dll
		)
else ( WIN32 )
	set(libsearch_srcs
		libsearch.py
		find.py
		__init__.py
		)
endif ( WIN32 )

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/__init__.py)

install_lib(${SWIG_MODULE_libsearch_REAL_NAME})
install_file(libsearch ${libsearch_srcs})
