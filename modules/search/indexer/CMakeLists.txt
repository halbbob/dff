FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

include_directories(${PYTHON_INCLUDE_PATH})
INCLUDE_DIRECTORIES(${QT_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${QT_QTCORE_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_HOME_DIRECTORY}/api/include)
include_directories(${CMAKE_HOME_DIRECTORY}/api/tree)
include_directories(${CMAKE_HOME_DIRECTORY}/api/index/)
include_directories(${CMAKE_HOME_DIRECTORY}/api/index/CLucene)

set(indexer_srcs
  indexer.cpp
)

SET_SOURCE_FILES_PROPERTIES(indexer.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(INDEXER python indexer.i ${indexer_srcs})
if (UNIX)
SWIG_LINK_LIBRARIES(INDEXER ${PYTHON_LIBRARIES} _libexceptions _libvfs _libtree _libindex)
else (UNIX)
  SWIG_LINK_LIBRARIES(INDEXER ${PYTHON_LIBRARIES} _libexceptions _libvfs  _libtree _libindex ${QT_QTCORE_LIBRARIES} ${QT_QTCLUCENE_LIBRARIES})
endif (UNIX)

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_INDEXER_REAL_NAME} PROPERTIES
  PREFIX "../"
  SUFFIX ".pyd"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

set(indexer_files
  INDEXER.py
)

install_lib(${SWIG_MODULE_INDEXER_REAL_NAME})
install_file(indexer ${indexer_files})
