FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})
include_directories(${PYTHON_INCLUDE_PATH})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_HOME_DIRECTORY}/api/include)

set(dummy_srcs
  dummy.cpp
  DummyNode.cpp)

SET_SOURCE_FILES_PROPERTIES(dummy.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(DUMMY python dummy.i ${dummy_srcs})
SWIG_LINK_LIBRARIES(DUMMY ${PYTHON_LIBRARIES} _libvariant _libexceptions _libtype _libvfs _libenv)

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
  set_target_properties (${SWIG_MODULE_DUMMY_REAL_NAME} PROPERTIES
    PREFIX "../"
    SUFFIX ".pyd"
    )
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

set(dummy_files
  DUMMY.py
  )

install_lib(${SWIG_MODULE_DUMMY_REAL_NAME})
install_file(dummy ${dummy_files})
