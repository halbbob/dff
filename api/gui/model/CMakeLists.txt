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
#  Solal Jacob <sja@digital-forensic.org>


SET(VFSITEMMODEL_SRCS
  vfsitemmodel.cpp 
)

set(VFSITEMMODEL_MOC_HDRS
../../include/vfsitemmodel.hpp
)


QT4_WRAP_CPP(VFSITEMMODEL_MOC_SRCS ${VFSITEMMODEL_MOC_HDRS})
INCLUDE_DIRECTORIES( ${CMAKE_CURRENT_BUILD_DIR}/../../include )


ADD_LIBRARY(vfsitemmodelcore STATIC  ${VFSITEMMODEL_SRCS} ${VFSITEMMODEL_MOC_SRCS})
target_link_libraries(vfsitemmodelcore ${QT_GUI_LIBRARY})


INCLUDE_DIRECTORIES(
    ${PYTHON_INCLUDE_PATH}
    ${SIP_INCLUDE_DIR}
    ${QT_INCLUDE_DIR}
    ${QT_QT_INCLUDE_DIR}
    ${QT_QTCORE_INCLUDE_DIR}

    ${CMAKE_CURRENT_SOURCE_DIR}
    ../../include
)

FILE(GLOB vfsitemmodel_files_sip python/*.sip)
set(SIP_EXTRA_FILES_DEPEND ${vfsitemmodel_files_sip})
ADD_SIP_PYTHON_MODULE(vfsitemmodel python/vfsitemmodel.sip vfsitemmodelcore ${QT_CORE_LIBRARY} ${QT_GUI_LIBRARY} )





#SET(QT_USE_QTMAIN true)
##SET_SOURCE_FILES_PROPERTIES(libvfs.i PROPERTIES CPLUSPLUS ON)
##SWIG_ADD_MODULE(libvfs python libvfs.i fso.cpp node.cpp vfile.cpp vfs.cpp)
##SWIG_LINK_LIBRARIES(libvfs ${PYTHON_LIBRARIES} _libsearch _libexceptions _libtype)
##if ( CMAKE_GENERATOR MATCHES "Visual Studio")
##set_target_properties (${SWIG_MODULE_libvfs_REAL_NAME} PROPERTIES
  ##PREFIX "../"
  ##SUFFIX ".pyd"
##)
##endif ( CMAKE_GENERATOR MATCHES "Visual Studio")
##set(vfs_srcs
  ##vfs.py
  ##__init__.py
  ##libvfs.py
##)
#
##install_lib(${SWIG_MODULE_libvfs_REAL_NAME})
##install_file(vfs ${vfs_srcs})
