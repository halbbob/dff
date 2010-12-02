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
#  Christophe Malinge <cma@digital-forensic.org>
#  Solal Jacob <sja@digital-forensic.org>

project (dff)

#### Basic Cmake definitions
cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake_modules/")

#### Project-wide requirements

# check 64 bit
if( "${CMAKE_SIZEOF_VOID_P}" EQUAL 4 )
  set( HAVE_64_BIT 0 )
else( "${CMAKE_SIZEOF_VOID_P}" EQUAL 4 )
  set( HAVE_64_BIT 1 )
endif( "${CMAKE_SIZEOF_VOID_P}" EQUAL 4 )

option(ENABLE_DEBUG "Compile using -g flag ? Useful for debugging" OFF)
if(UNIX)
  if(ENABLE_DEBUG)
    add_definitions(-D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -g)
    message(STATUS "Will use -g for debugging -- yes")
  else(ENABLE_DEBUG)
#change flag here
    add_definitions(-D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -g)
    message(STATUS "Will use -g for debugging -- no")
  endif(ENABLE_DEBUG)
endif(UNIX)
# $> cmake -DENABLE_DEBUG:BOOLEAN=OFF

# Set installation mode, include all items (*.py, ...) Default is development mode
option(INSTALL "Start installation mode ?" OFF)
IF(INSTALL)
  message(STATUS "Preparing installation mode")
ELSE(INSTALL)
  message(STATUS "Preparing development mode")
ENDIF(INSTALL)

IF (WIN32)
  option(WINALL "Package with windows Dependencies ?" OFF)
  IF(WINALL)
    message(STATUS "Packaging windows version with dependencies")
  ELSE(WINALL)
    message(STATUS "Packaging windows version without dependencies")
  ENDIF(WINALL)
ENDIF(WIN32)

## Swig
find_package(SWIG REQUIRED)
include(${SWIG_USE_FILE})

STRING (COMPARE LESS "${SWIG_VERSION}" "1.3.38" SWIGOK)

if (${SWIGOK})
  MESSAGE(FATAL_ERROR "Need SWIG version >= 1.3.38 (current version is ${SWIG_VERSION})")
endif (${SWIGOK})

# Project-wide swig options
#SET(CMAKE_SWIG_FLAGS "-py3")

option(DISABLE_SWIG_THREADING "Wrap cpp code to python without -threads" OFF)
if(DISABLE_SWIG_THREADING)
  message(STATUS "Will we use swig -threads -- no")
else()
  #message(STATUS "Will we use swig -threads -- yes")
  set(CMAKE_SWIG_FLAGS -O -threads)
endif(DISABLE_SWIG_THREADING)
# $> cmake -DDISABLE_SWIG_THREADING:BOOLEAN=ON

find_library(HAVE_FUSE NAMES fuse)
if(NOT HAVE_FUSE)
  message(STATUS "(Optionnal) fuse library not found; file system module 'fuse' will not be built")
endif(NOT HAVE_FUSE)

IF(WIN32)
  SET(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} -DWIN32 -DSWIGWIN)
ENDIF(WIN32)


## Python check
FIND_PACKAGE(PythonInterp REQUIRED)
execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()" OUTPUT_VARIABLE PYTHON_SITE_PACKAGES_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()" OUTPUT_VARIABLE PYTHON_SITE_PACKAGES_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_version; print get_python_version()" OUTPUT_VARIABLE PYTHON_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
if (UNIX)
  if (APPLE)
    execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_config_vars; print get_config_vars()[\"PYTHONFRAMEWORKPREFIX\"] + \"/\" + get_config_vars()[\"LDLIBRARY\"]" OUTPUT_VARIABLE PYTHON_LIBRARIES OUTPUT_STRIP_TRAILING_WHITESPACE)
  else ()
    execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_config_vars; print get_config_vars()[\"LIBDIR\"] + \"/\" + get_config_vars()[\"LDLIBRARY\"]" OUTPUT_VARIABLE PYTHON_LIBRARIES OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif (APPLE)
  execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_inc; print get_python_inc()" OUTPUT_VARIABLE PYTHON_INCLUDE_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_config_vars; print get_config_vars()[\"BINDIR\"]" OUTPUT_VARIABLE PYTHON_BIN_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT PYTHON_LIBRARIES)
    message(SEND_ERROR "No Python library found ; please install Python package, at least version 2.5.")
  else(NOT PYTHON_LIBRARIES)
    message(STATUS "Python library found: ${PYTHON_LIBRARIES}")
  endif(NOT PYTHON_LIBRARIES)
  if(NOT EXISTS ${PYTHON_INCLUDE_PATH}/Python.h)
    message(SEND_ERROR "No Python include/header file found; install Python development package.")
  else(NOT EXISTS ${PYTHON_INCLUDE_PATH}/Python.h)
    message(STATUS "Python header found: ${PYTHON_INCLUDE_PATH}")
  endif(NOT EXISTS ${PYTHON_INCLUDE_PATH}/Python.h)
else (UNIX)
  find_package(PythonLibs)
  find_package(PythonInterp)
  SET(PYTHON_BIN_PATH ${PYTHON_EXECUTABLE})
# FIXME for windows validate presence of Python.h in PYTHON_INCLUDE_PATH
endif(UNIX)

message(STATUS "Python in: ${PYTHON_BIN_PATH}")


#XXX SIP TEST 
FIND_PACKAGE(PythonLibrary REQUIRED)
FIND_PACKAGE(SIP REQUIRED)
FIND_PACKAGE(PyQt4 REQUIRED)
INCLUDE(PythonMacros)
INCLUDE(SIPMacros)
separate_arguments(PYQT4_SIP_FLAGS)
SET(SIP_INCLUDES ${PYQT4_SIP_DIR})
SET(SIP_CONCAT_PARTS 1)
SET(SIP_EXTRA_OPTIONS ${PYQT4_SIP_FLAGS})
IF (NOT MSVC)
  ADD_DEFINITIONS(-fPIC)
ENDIF ()
# Useless ; only for SIP test
#FIND_PACKAGE(Qt4 REQUIRED)
#INCLUDE(${QT_USE_FILE})

#XXX SIP TEST

## Python-magic check for Unix only
if(UNIX)
  execute_process(COMMAND ${PYTHON_EXECUTABLE} -c "import magic; print magic.__file__" OUTPUT_VARIABLE PYTHON_MAGIC_PATH ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT PYTHON_MAGIC_PATH)
    message(STATUS "Python magic not found. Not needed at build step but mandatory to start DFF.")
  else(NOT PYTHON_MAGIC_PATH)
    message(STATUS "Python magic found: ${PYTHON_MAGIC_PATH}")
  endif(NOT PYTHON_MAGIC_PATH)
endif(UNIX)

## Python-QT bindings check
execute_process(COMMAND ${PYTHON_EXECUTABLE} -c "import PyQt4; print PyQt4.__path__[0]" OUTPUT_VARIABLE PYTHON_QT4_PATH ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT PYTHON_QT4_PATH)
  message(STATUS "Python QT4 bindings not found. Not needed at build step but mandatory to start DFF.")
else(NOT PYTHON_QT4_PATH)
  message(STATUS "Python QT4 libraries bindings found: ${PYTHON_QT4_PATH}")
endif(NOT PYTHON_QT4_PATH)

## QScintilla python bindings check, for IDE
execute_process(COMMAND ${PYTHON_EXECUTABLE} -c "from PyQt4 import Qsci; print Qsci.__file__" OUTPUT_VARIABLE PYTHON_QT4_QSCI_PATH ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT PYTHON_QT4_QSCI_PATH)
  message(STATUS "Python QScintilla bindings not found. Not needed at build step but mandatory to start DFF.")
else(NOT PYTHON_QT4_QSCI_PATH)
  message(STATUS "Python QScintilla library bindings found: ${PYTHON_QT4_QSCI_PATH}")
endif(NOT PYTHON_QT4_QSCI_PATH)

## PyQt resource compiler check, to generate icons
find_program(PYTHON_QT4_RCC NAMES pyrcc4 PATHS ${CMAKE_SYSTEM_PROGRAM_PATH} ${PYTHON_QT4_PATH}/bin)
if(PYTHON_QT4_RCC)
  message(STATUS "Python Qt4 resource compiler found: ${PYTHON_QT4_RCC}")
else(PYTHON_QT4_RCC)
  message(SEND_ERROR "Python Qt4 resource compiler not found.")
endif(PYTHON_QT4_RCC)



# Backing up original install prefix, some files have to sit elsewhere than python path, see at the end of this file.
SET(CMAKE_INSTALL_ORIG_PREFIX ${CMAKE_INSTALL_PREFIX})
# Install prefix used by Python installer.
SET(CMAKE_INSTALL_PREFIX ${PYTHON_SITE_PACKAGES_PATH}/${CMAKE_PROJECT_NAME}/)

## Main purpose of this macro if to copy Python files at install.
# It also deploys .py files in build directory if there is one.
LIST(APPEND PYC_FILES "")
macro(install_file target_name)
  foreach(file ${ARGN})
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${file})
      # Be carreful, SWiG generate .py files, which sits in builddir,
      #  so we have to check if file exists in source dir before copying it.
      add_custom_target("builddeploy.${target_name}.${file}" ALL
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
	  ${CMAKE_CURRENT_SOURCE_DIR}/${file} ${CMAKE_CURRENT_BINARY_DIR}/${file}
	)
    endif(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${file})
    IF (INSTALL)
      add_custom_target("${target_name}.${file}" ALL)
      FILE(RELATIVE_PATH rel ${CMAKE_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})
      IF(NOT WIN32 AND UNIX)
		install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${file} DESTINATION ${PYTHON_SITE_PACKAGES_PATH}/${CMAKE_PROJECT_NAME}/${rel})
	  ELSE(NOT WIN32 AND UNIX)
	    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${file} DESTINATION /${CMAKE_PROJECT_NAME}/${rel})
		IF(${file} MATCHES "^.*\\.py$" AND NOT ${rel} STREQUAL "")
		# Store every .py files in a list, renaming each file to .pyc it
		# will handle Windows uninstall ; runtime created *.pyc are not
		# removed by uninstaller.
			STRING(REPLACE "\\" "\\\\" PYCFILE "${rel}/${file}c")
			STRING(REPLACE "/" "\\\\" PYCFILE ${PYCFILE})
			LIST(APPEND PYC_FILES "${PYCFILE}")
			SET(PYC_FILES "${PYC_FILES}" PARENT_SCOPE)
		ENDIF(${file} MATCHES "^.*\\.py$" AND NOT ${rel} STREQUAL "")
	  ENDIF(NOT WIN32 AND UNIX)
    ENDIF (INSTALL)
  endforeach(file ${ARGN}) 
endmacro(install_file target_name)

## Macro to cop` lib at install
macro(install_lib target_name)
  FILE(RELATIVE_PATH rel ${CMAKE_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})
  IF(NOT WIN32 AND UNIX)
    INSTALL (TARGETS ${target_name} DESTINATION ${PYTHON_SITE_PACKAGES_PATH}/${CMAKE_PROJECT_NAME}/${rel})
  ELSE(NOT WIN32 AND UNIX)
	INSTALL (TARGETS ${target_name} DESTINATION /${CMAKE_PROJECT_NAME}/${rel})
  ENDIF(NOT WIN32 AND UNIX)	
endmacro(install_lib)

#### Deploying package file and DFF startup files
set(dff_scripts
  __init__.py
#  dff.py
#  dff-gui.py
)

install_file(dff_launch ${dff_scripts})

# Override deployment of launcher to add proper Python binary prefix
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/dff.py ${CMAKE_CURRENT_BINARY_DIR}/dff.py)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/dff-gui.py ${CMAKE_CURRENT_BINARY_DIR}/dff-gui.py)

# Create launcher. Replace CMake variables in it, used after install.
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ressources/linux_launcher.sh ${CMAKE_CURRENT_BINARY_DIR}/dff)

if (APPLE)
  SET(CMAKE_SHARED_LIBRARY_SUFFIX ".so")
  SET(CMAKE_SHARED_MODULE_SUFFIX ".so")
endif(APPLE)

#### Subdirectories to recurse
add_subdirectory (api)
add_subdirectory (modules)
add_subdirectory (ui)
add_subdirectory (ressources)
if (NOT UNIX AND WINALL)
  add_subdirectory (Prerequisites)
endif(NOT UNIX AND WINALL)

SET(CPACK_SET_DESTDIR "ON")
#### Project install

SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Digital Forensics Framework")
SET(CPACK_PACKAGE_VENDOR "ArxSys")
SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYRIGHT")
SET(CPACK_PACKAGE_VERSION_MAJOR "0") 
SET(CPACK_PACKAGE_VERSION_MINOR "8")
SET(CPACK_PACKAGE_VERSION_PATCH "0")
SET(CPACK_PACKAGE_INSTALL_DIRECTORY "DFF")

IF(WIN32 AND NOT UNIX)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dff.py
	DESTINATION /${CMAKE_PROJECT_NAME}
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dff-gui.py
	DESTINATION /${CMAKE_PROJECT_NAME}
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	RENAME dff-gui.pyw)
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/ressources/dff.ico
    DESTINATION /${CMAKE_PROJECT_NAME}/ressources/)

  SET(CPACK_MONOLITHIC_INSTALL "ON")
	
  SET(CPACK_PACKAGE_ICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\ressources\\\\arxsys.bmp")
  SET(CPACK_BUNDLE_ICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\ressources\\\\arxsys.bmp")
  SET(CPACK_NSIS_MUI_ICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\ressources\\\\dff.ico")
  SET(CPACK_NSIS_MUI_UNIICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\ressources\\\\dff.ico")
  SET(CPACK_NSIS_DISPLAY_NAME "Digital Forensics Framework")
  SET(CPACK_NSIS_HELP_LINK "http://www.digital-forensic.org/")
  SET(CPACK_NSIS_URL_INFO_ABOUT "http://www.arxsys.fr/")
  SET(CPACK_NSIS_CONTACT "contact@arxsys.fr")
  SET(CPACK_NSIS_MODIFY_PATH OFF)
  SET(CPACK_NSIS_COMPRESSOR "/SOLID lzma")
  SET(CPACK_GENERATOR "NSIS")
  SET(CPACK_NSIS_FULL_INSTALL
    "
	 ReadRegStr \\\$R0 HKLM \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\dff\\\" \\\"DisplayVersion\\\"
	 StrCmp \\\$R0 \\\"\\\" cont
	 ReadRegStr \\\$R1 HKLM \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\dff\\\" \\\"UninstallString\\\"
     StrCmp \\\$R0 \\\"\\\" cont
     MessageBox MB_YESNO|MB_ICONQUESTION \\\"Other DFF version \\\$R0 installation found.\\\$\\\\n\\\$\\\\nClick 'YES' to uninstall it first, or 'NO' to overwrite version already installed.\\\" IDYES uninst
     Goto cont
	 end:
	  MessageBox MB_OK|MB_ICONEXCLAMATION \\\"Error uninstalling DFF version \\\$R0.\\\"
	  Goto cont
     uninst:
      ClearErrors
      ExecWait '$R1 _?=$INSTDIR'
      IfErrors end
	  MessageBox MB_OK|MB_ICONINFORMATION \\\"Uninstalling previous DFF version \\\$R0 done, continue with install.\\\"
     cont:
	  File /r \\\"\\\${INST_DIR}\\\\*.*\\\"
	")
  SET(CPACK_NSIS_EXTRA_INSTALL_COMMANDS       
    "
     SetOutPath \\\"$INSTDIR\\\\dff\\\"
     CreateShortCut \\\"$DESKTOP\\\\DFF (shell).lnk\\\" \\\"$INSTDIR\\\\dff\\\\dff.py\\\" \\\"\\\" \\\"$INSTDIR\\\\dff\\\\ressources\\\\dff.ico\\\" 
     CreateShortCut \\\"$DESKTOP\\\\DFF (gui).lnk\\\" \\\"$INSTDIR\\\\dff\\\\dff-gui.pyw\\\" \\\"\\\" \\\"$INSTDIR\\\\dff\\\\ressources\\\\dff.ico\\\"  
     CreateShortCut \\\"$SMPROGRAMS\\\\Digital Forensics Framework\\\\DFF (shell).lnk\\\" \\\"$INSTDIR\\\\dff\\\\dff.py\\\" \\\"\\\" \\\"$INSTDIR\\\\dff\\\\ressources\\\\dff.ico\\\"  
     CreateShortCut \\\"$SMPROGRAMS\\\\Digital Forensics Framework\\\\DFF (gui).lnk\\\" \\\"$INSTDIR\\\\dff\\\\dff-gui.pyw\\\" \\\"\\\" \\\"$INSTDIR\\\\dff\\\\ressources\\\\dff.ico\\\"  
    ")
	
	# *.pyc files are not deleted by installer, because they are created at
	# runtime. So, below, we force deletion of those files.
    FOREACH(PYCFILE ${PYC_FILES})
	  SET(CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS
	  "${CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS}
	  Delete \\\"$INSTDIR\\\\dff\\\\${PYCFILE}\\\"")
    ENDFOREACH(PYCFILE ${PYC_FILES})
  
	SET(CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS
    "
	${CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS}
	 Delete \\\"$DESKTOP\\\\DFF (shell).lnk\\\"
	 Delete \\\"$DESKTOP\\\\DFF (gui).lnk\\\"
	 Delete \\\"$SMPROGRAMS\\\\Digital Forensics Framework\\\\DFF (shell).lnk\\\"
	 Delete \\\"$SMPROGRAMS\\\\Digital Forensics Framework\\\\DFF (gui).lnk\\\"
	")
	
	#MESSAGE(STATUS ${CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS})
	
	
  if (WINALL)
    if (HAVE_64_BIT)
      SET(CPACK_SYSTEM_NAME "win64_all_in_one")
    else(HAVE_64_BIT)
      SET(CPACK_SYSTEM_NAME "win32_all_in_one")
    endif(HAVE_64_BIT)
    SET(CPACK_NSIS_EXTRA_INSTALL_COMMANDS ${CPACK_NSIS_EXTRA_INSTALL_COMMANDS}
      "
       MessageBox MB_YESNO \\\"Install Python 2.6.5 ? \\\" /SD IDYES IDNO endPython
        ExecWait '\\\"msiexec\\\" /i \\\"Prerequisites\\\\python-2.6.5.msi\\\" /passive'
        Goto endPython   
       endPython:
        MessageBox MB_YESNO \\\"Install PyQt 4.7.4-1 ? \\\" /SD IDYES IDNO endPyQt
        ExecWait '\\\"Prerequisites\\\\PyQt-Py2.6-gpl-4.7.4-1.exe\\\"'
        Goto endPyQt
       endPyQt:
       MessageBox MB_YESNO \\\"Install Microsoft Visual Studio DLL dependencies ? \\\" /SD IDYES IDNO endVS
        ExecWait '\\\"Prerequisites\\\\vcredist_x86.exe\\\" /q:a'
        Goto endVS
       endVS:
       RMDir /r \\\"$INSTDIR\\\\dff\\\\Prerequisites\\\"
      ")
  endif(WINALL)
  SET(CPACK_SOURCE_GENERATOR "ZIP")
  
  SET(CMAKE_INSTALL_PREFIX "/dff/")
  
ELSE(WIN32 AND NOT UNIX)
  SET(CPACK_SOURCE_GENERATOR "TGZ")
#  SET(CPACK_SOURCE_IGNORE_FILES "") 
  SET(CPACK_GENERATOR "DEB" "RPM")
ENDIF(WIN32 AND NOT UNIX)

IF(NOT WIN32 AND UNIX)
#debian specific
  SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Malinge Christophe packaging@digital-forensic.org")
  execute_process ( COMMAND uname -m  OUTPUT_VARIABLE CURRENT_ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)
  IF("${CURRENT_ARCH}" STREQUAL "x86_64")
    SET(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
  ELSE("${CURRENT_ARCH}" STREQUAL "x86_64")
    SET(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "i386")
  ENDIF("${CURRENT_ARCH}" STREQUAL "x86_64")
  SET(CPACK_DEBIAN_PACKAGE_DEPENDS "python${PYTHON_VERSION} (>=${PYTHON_VERSION}.0), python-qt4 (>= 4.4.0), python-qscintilla2 (>= 2.2), python-magic (>= 4.26)")
  SET(CPACK_DEBIAN_PACKAGE_SECTION "utils")

#rpm specific
  SET(CPACK_RPM_PACKAGE_ARCHITECTURE "${CURRENT_ARCH}")
  SET(CPACK_RPM_PACKAGE_GROUP "Applications/System")
  SET(CPACK_RPM_PACKAGE_LICENSE "GPLV2")
  SET(CPACK_RPM_PACKAGE_REQUIRES "python >= ${PYTHON_VERSION}.0, PyQt4 >= 4.4.0, qscintilla-python >= 2.2, python-magic >= 4.26")

  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dff.py
    DESTINATION ${PYTHON_SITE_PACKAGES_PATH}/${CMAKE_PROJECT_NAME}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
ENDIF(NOT WIN32 AND UNIX)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dff.py
  DESTINATION ${PYTHON_SITE_PACKAGES_PATH}/${CMAKE_PROJECT_NAME}
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

if (UNIX)
# Install binary  launcher, icons, shortcuts.
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dff
  DESTINATION ${CMAKE_INSTALL_ORIG_PREFIX}/bin
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/ressources/dff.png ${CMAKE_CURRENT_SOURCE_DIR}/ressources/dff.xpm
  DESTINATION ${CMAKE_INSTALL_ORIG_PREFIX}/share/pixmaps
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/ressources/dff.desktop
  DESTINATION ${CMAKE_INSTALL_ORIG_PREFIX}/share/applications
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif(UNIX)

INCLUDE(CPack)
ENABLE_TESTING()
SUBDIRS(testsuite)
