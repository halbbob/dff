FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

include_directories(${PYTHON_INCLUDE_PATH})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_HOME_DIRECTORY}/api/include)

#add_definitions(-Wall -Wunused -Wextra)

set(ntfs_srcs
  ntfs.cpp
  boot.cpp
  mftentry.cpp
  mftfile.cpp
  attribute.cpp
  ntfsnode.cpp
  attributes/data.cpp
  attributes/bitmap.cpp
  attributes/filename.cpp
  attributes/standardinformation.cpp
  attributes/attributelist.cpp
  attributes/indexroot.cpp
  attributes/reparsepoint.cpp
  attributes/indexallocation.cpp
  attributes/securitydescriptor.cpp
)

SET_SOURCE_FILES_PROPERTIES(ntfs.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(NTFS python ntfs.i ${ntfs_srcs})
SWIG_LINK_LIBRARIES(NTFS ${PYTHON_LIBRARIES} _libvariant _libexceptions _libtype _libvfs _libenv)

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_NTFS_REAL_NAME} PROPERTIES
  PREFIX "../"
  SUFFIX ".pyd"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

set(ntfs_files
  NTFS.py
)

install_lib(${SWIG_MODULE_NTFS_REAL_NAME})
install_file(ntfs ${ntfs_files})
