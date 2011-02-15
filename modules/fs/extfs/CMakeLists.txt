FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

include_directories(${PYTHON_INCLUDE_PATH})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_HOME_DIRECTORY}/api/include)
include_directories(${CMAKE_HOME_DIRECTORY}/api/tree)

set(extfs_srcs
  extfs.cpp
  Directory.cpp
  SymLink.cpp
  Journal.cpp
  JournalType.tpp
  FileNameRecovery.cpp
  CustomResults.cpp
  FsStat.cpp
  InodeStat.cpp
  JournalStat.cpp
  InodesList.cpp
  InodeUtils.cpp
  SuperBlockUtils.cpp
  ExtfsNode.cpp
  ExtfsRawDataNode.cpp
  ExtfsSymLinkNode.cpp
  ExtfsShiftNode.cpp
  BlkList.cpp
  DirLs.cpp
  MfsoAttrib.cpp
  OrphansInodes.cpp
  data_structure/InodeStructure.cpp
  data_structure/SuperBlock.cpp
  data_structure/BootCode.cpp
  data_structure/GroupDescriptor.cpp
  data_structure/Inode.cpp
  data_structure/DirEntry.cpp
  data_structure/SuperBlockStructure.cpp
  data_structure/ExtendedAttr.cpp
  data_structure/Ext4Extents.cpp
)

SET_SOURCE_FILES_PROPERTIES(extfs.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(EXTFS python extfs.i ${extfs_srcs})
SWIG_LINK_LIBRARIES(EXTFS ${PYTHON_LIBRARIES} _libexceptions _libtypes _libvfs _libtree)

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_EXTFS_REAL_NAME} PROPERTIES
  PREFIX "../"
  SUFFIX ".pyd"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

set(extfs_files
  EXTFS.py
)

install_lib(${SWIG_MODULE_EXTFS_REAL_NAME})
install_file(extfs ${extfs_files})
