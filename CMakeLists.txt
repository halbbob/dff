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
  SET(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} -DSWIGWORDSIZE64)
  set( HAVE_64_BIT 1 )
endif( "${CMAKE_SIZEOF_VOID_P}" EQUAL 4 )

option(ENABLE_DEBUG "Compile using -g flag ? Useful for debugging" OFF)
add_definitions(-D__STDC_LIMIT_MACROS)
if(UNIX)
  if(ENABLE_DEBUG)
    add_definitions(-D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -g -Wall)
    message(STATUS "Will use -g for debugging -- yes")
  else(ENABLE_DEBUG)
#change flag here
    add_definitions(-D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -O2)
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


find_package(AFF)

if (CMAKE_GENERATOR MATCHES "Unix Makefiles")
   message(STATUS "current build dir")
   message(STATUS "build command is based on unix Makefiles")
   #add_custom_command (OUTPUT api COMMAND make WORKING_DIRECTORY api)
   add_custom_target (modules ALL COMMAND make -i WORKING_DIRECTORY modules)
   #add_custom_command (OUTPUT ui COMMAND make WORKING_DIRECTORY ui/)
   #add_custom_command (OUTPUT all COMMAND make DEPENDS api modules ui)
endif (CMAKE_GENERATOR MATCHES "Unix Makefiles")

# Project-wide swig options
#SET(CMAKE_SWIG_FLAGS "-py3")

option(DISABLE_SWIG_THREADING "Wrap cpp code to python without -threads" OFF)
if(DISABLE_SWIG_THREADING)
  message(STATUS "Will we use swig -threads -- no")
else()
  #message(STATUS "Will we use swig -threads -- yes")
  #set(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} -O -threads)
  set(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} -threads)
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
execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())" OUTPUT_VARIABLE PYTHON_SITE_PACKAGES_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())" OUTPUT_VARIABLE PYTHON_SITE_PACKAGES_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_version; print(get_python_version())" OUTPUT_VARIABLE PYTHON_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
if (UNIX)
  if (APPLE)
    execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_config_vars; print(get_config_vars()[\"PYTHONFRAMEWORKPREFIX\"] + \"/\" + get_config_vars()[\"LDLIBRARY\"])" OUTPUT_VARIABLE PYTHON_LIBRARIES OUTPUT_STRIP_TRAILING_WHITESPACE)
  else ()
    execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_config_vars; print(get_config_vars()[\"LIBDIR\"] + \"/\" + get_config_vars()[\"LDLIBRARY\"])" OUTPUT_VARIABLE PYTHON_LIBRARIES OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif (APPLE)
  execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_inc; print(get_python_inc())" OUTPUT_VARIABLE PYTHON_INCLUDE_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_config_vars; print(get_config_vars()[\"BINDIR\"])" OUTPUT_VARIABLE PYTHON_BIN_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)
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


FIND_PACKAGE(PythonLibrary REQUIRED)
FIND_PACKAGE(PyQt4 REQUIRED)
INCLUDE(PythonMacros)
IF (NOT MSVC)
  ADD_DEFINITIONS(-fPIC)
ENDIF ()
#FIND_PACKAGE(Qt4 REQUIRED)
#INCLUDE(${QT_USE_FILE})

if(UNIX)
# Search for gzip program, to compress manpage for Unix
  find_program(GZIP_TOOL
               NAMES gzip
               PATHS /bin
               /usr/bin
               /usr/local/bin)
  if(NOT GZIP_TOOL)
    message(FATAL_ERROR "Unable to find 'gzip' program")
  endif(NOT GZIP_TOOL)
endif(UNIX)

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

## PyQt linguist transalation updater check, to create or update translation
## files
find_program(PYTHON_QT4_LANGUAGE NAMES pylupdate4 PATHS	${CMAKE_SYSTEM_PROGRAM_PATH} ${PYTHON_QT4_PATH}/bin ${PYTHON_QT4_PATH})
if(PYTHON_QT4_LANGUAGE)
  message(STATUS "Python Qt4 linguist translation files updater found: ${PYTHON_QT4_LANGUAGE}")
else(PYTHON_QT4_LANGUAGE)
  message(STATUS "Python Qt4 linguist translation files updater not found, unable to check for new tranlatable strings.")
endif(PYTHON_QT4_LANGUAGE)

## QT .ts to .qm compiler, used by translator objects
find_program(QT_LANGUAGE_COMPILER NAMES lrelease lrelease-qt4 PATHS ${CMAKE_SYSTEM_PROGRAM_PATH} ${PYTHON_QT4_PATH}/bin ${PYTHON_QT4_PATH})
if(QT_LANGUAGE_COMPILER)
  message(STATUS "QT translation compiler found: ${QT_LANGUAGE_COMPILER}")
else(QT_LANGUAGE_COMPILER)
  message(ERROR "QT translation compiler not found.")
endif(QT_LANGUAGE_COMPILER)

## PyQt UI compiler check, to generate widgets
find_program(PYTHON_QT4_UIC NAMES pyuic4 pyuic4.bat PATHS ${CMAKE_SYSTEM_PROGRAM_PATH} ${PYTHON_QT4_PATH}/bin ${PYTHON_QT4_PATH})
if(PYTHON_QT4_UIC)
  message(STATUS "Python Qt4 user interface compiler found: ${PYTHON_QT4_UIC}")
else(PYTHON_QT4_UIC)
  message(SEND_ERROR "Python Qt4 user interface compiler not found.")
endif(PYTHON_QT4_UIC)

## PyQt resource compiler check, to generate icons
find_program(PYTHON_QT4_RCC NAMES pyrcc4 PATHS ${CMAKE_SYSTEM_PROGRAM_PATH} ${PYTHON_QT4_PATH}/bin ${PYTHON_QT4_PATH})
if(PYTHON_QT4_RCC)
  message(STATUS "Python Qt4 resource compiler found: ${PYTHON_QT4_RCC}")
else(PYTHON_QT4_RCC)
  message(SEND_ERROR "Python Qt4 resource compiler not found.")
endif(PYTHON_QT4_RCC)

option(ENABLE_INDEXER "Compile and enable Lucene indexing engine" OFF)
if (ENABLE_INDEXER)
   ## CLucene indexer library check
   find_library(CLUCENE_LIBRARY NAMES clucene)
   if(CLUCENE_LIBRARY)
	message(STATUS "CLucene indexing library found: ${CLUCENE_LIBRARY}")
   else(CLUCENE_LIBRARY)
	message(STATUS "CLucene indexing library not found.")
   endif(CLUCENE_LIBRARY)
   # Check for header, usually sits in /usr/lib on linux, strange !
   get_directory_property(cmake_include_directories INCLUDE_DIRECTORIES)
   find_path(CLUCENE_CONFIG_INCLUDE_PATH NAMES clucene-config.h ${cmake_include_directories})
   if(CLUCENE_CONFIG_INCLUDE_PATH)
	message(STATUS "CLucene indexing library config header file found in common include directories.")
   else(CLUCENE_CONFIG_INCLUDE_PATH)
	find_path(CLUCENE_CONFIG_INCLUDE_PATH NAMES CLucene/clucene-config.h PATHS /usr/lib /usr/local/lib)
    	if(CLUCENE_CONFIG_INCLUDE_PATH)
		message(STATUS "CLucene indexing library config header file found in: ${CLUCENE_CONFIG_INCLUDE_PATH}/CLucene")
	else(CLUCENE_CONFIG_INCLUDE_PATH)
		message(STATUS "CLucene indexing library config header file not found.")
  	endif(CLUCENE_CONFIG_INCLUDE_PATH)
   endif(CLUCENE_CONFIG_INCLUDE_PATH)
endif(ENABLE_INDEXER)

## LibPFF check for PFF module, added separatly on windows
# Need libbfio separate installation for DFF to be able to use PFF.
# To summarize, install http://libbfio.sf.net first, before http://libpff.sf.net .
if(UNIX)
  if(INSTALL)
    # Link with static version at install, until PFF be added to respective packages streams
    find_library(PFF_MAIN_LIBRARY NAMES libpff.a)
  else(INSTALL)
    find_library(PFF_MAIN_LIBRARY NAMES pff)
  endif(INSTALL)
  if(PFF_MAIN_LIBRARY)
    message(STATUS "PFF library found: ${PFF_MAIN_LIBRARY}")
    if(INSTALL)
      find_library(PFF_BFIO_LIBRARY NAMES libbfio.a)
    else(INSTALL)
      find_library(PFF_BFIO_LIBRARY NAMES bfio)
    endif(INSTALL)
    if(PFF_BFIO_LIBRARY)
      message(STATUS "Separate PFF bfio library found: ${PFF_BFIO_LIBRARY}")
    else(PFF_BFIO_LIBRARY)
      message(STATUS "Separate PFF bfio library not found, unable to use PFF library, PFF module will not be build.")
    endif(PFF_BFIO_LIBRARY)
  else(PFF_MAIN_LIBRARY)
    message(STATUS "PFF library not found, PFF module will not be build.")
  endif(PFF_MAIN_LIBRARY)
endif(UNIX)


## LibTRE check for regexp and fuzzy support in search API
if ( UNIX )
	find_library(TRE_LIBRARY NAMES tre PATH_SUFFIXES /usr /usr/local)
	if (TRE_LIBRARY)
		find_path(TRE_INCLUDE tre PATH /usr/include /usr/local/include)
		if ( TRE_INCLUDE )
		     	message(STATUS "has tre include : ${TRE_INCLUDE}")
			INCLUDE_DIRECTORIES(${TRE_INCLUDE})
			add_definitions (-DHAVE_TRE)
			message(STATUS "tre library found: ${TRE_LIBRARY}, regexp and fuzzy match activated")
		else ( TRE_INCLUDE )
			message(STATUS "tre library not found, regexp and fuzzy match not activated")
		endif ( TRE_INCLUDE )
	endif ( TRE_LIBRARY )
else ( UNIX )
	message(STATUS "tre library found: regexp and fuzzy match activated")
	add_definitions (-DHAVE_TRE)
endif ( UNIX )

# Backing up original install prefix, some files have to sit elsewhere than python path, see at the end of this file.
SET(CMAKE_INSTALL_ORIG_PREFIX ${CMAKE_INSTALL_PREFIX})
# Install prefix used by Python installer.
SET(CMAKE_INSTALL_PREFIX ${PYTHON_SITE_PACKAGES_PATH}/${CMAKE_PROJECT_NAME}/)

## Main purpose of this macro if to copy Python files at install.
# It also deploys .py files in build directory if there is one.
LIST(APPEND PYC_FILES "")
macro(install_file target_name)
  foreach(file ${ARGN})
    # Be carreful:
    #  - SWiG generate .py files, which sits in builddir, so we have to check
    # if file exists in source dir before copying it.
    #  - Several files are configured at the cmake configure step, moving from
    # source to build dir, mostly to replace versions variables, so we have to
    # check if file is missing from build dir before copying it at build step.
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${file} AND NOT EXISTS ${CMAKE_CURRENT_BINARY_DIR}/${file})
      add_custom_target("builddeploy.${target_name}.${file}" ALL
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
	  ${CMAKE_CURRENT_SOURCE_DIR}/${file} ${CMAKE_CURRENT_BINARY_DIR}/${file}
	)
    endif(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${file} AND NOT EXISTS ${CMAKE_CURRENT_BINARY_DIR}/${file})
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

## Macro to copy lib at install
macro(install_lib target_name)
  FILE(RELATIVE_PATH rel ${CMAKE_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})
  IF(NOT WIN32 AND UNIX)
    INSTALL (TARGETS ${target_name} DESTINATION ${PYTHON_SITE_PACKAGES_PATH}/${CMAKE_PROJECT_NAME}/${rel})
  ELSE(NOT WIN32 AND UNIX)
	INSTALL (TARGETS ${target_name} DESTINATION /${CMAKE_PROJECT_NAME}/${rel})
  ENDIF(NOT WIN32 AND UNIX)	
endmacro(install_lib)

if (APPLE)
  SET(CMAKE_SHARED_LIBRARY_SUFFIX ".so")
  SET(CMAKE_SHARED_MODULE_SUFFIX ".so")
endif(APPLE)

## Macro to convert XML ui files to Python Qt widget code
# We are unable to use pyuic4 with QTreeWidget as base class
# It is why <widget class="QWidget" name="useless" /> has to be appended to .ui
# files using QTreeWidget. Be carreful, QtDesigner place this second widget at
# the end of the .ui file ; which make pyuic4 fails to compile.
macro(uitopy_file target_name)
  foreach(UIFILE ${ARGN})
    string(REGEX REPLACE "^(.*)\\.ui$" "ui_\\1.py" PYUICFILE ${UIFILE})
    add_custom_target("${target_name}.${UIFILE}" ALL
      COMMAND ${PYTHON_QT4_UIC} -o ${CMAKE_CURRENT_BINARY_DIR}/${PYUICFILE} ${CMAKE_CURRENT_SOURCE_DIR}/${UIFILE}
      SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/${UIFILE}
      )
  endforeach(UIFILE ${ui_dialog_files})
endmacro(uitopy_file)



#### Project install
SET(CPACK_SET_DESTDIR "ON")

SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Digital Forensics Framework")
SET(CPACK_PACKAGE_VENDOR "ArxSys")
SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYRIGHT")
# In order to provide top-level setting of DFF version, three variables bellow
# must be used in those two files :
#  ui/gui/gui.py
#  ui/ui.py
# See corresponding CMakeLists.txt for CONFIGURE_FILE.
SET(CPACK_PACKAGE_VERSION_MAJOR "1") 
SET(CPACK_PACKAGE_VERSION_MINOR "1")
SET(CPACK_PACKAGE_VERSION_PATCH "0")
SET(CPACK_PACKAGE_INSTALL_DIRECTORY "DFF")

#### Project API versionning
set(API_DEVICES_VERSION "0.4.0")
set(API_ENV_VERSION "1.1.0")
set(API_EXCEPTIONS_VERSION "1.0.0")
set(API_GUI_VERSION "1.1.0")
set(API_LOADER_VERSION "1.3.0")
set(API_MAGIC_VERSION "1.7.0")
set(API_MANAGER_VERSION "1.0.0")
set(API_MODULE_VERSION "1.0.0")
set(API_SEARCH_VERSION "1.0.0")
set(API_TASKMANAGER_VERSION "1.1.0")
set(API_TREE_VERSION "1.0.0")
set(API_TYPE_VERSION "1.0.0")
set(API_VARIANT_VERSION "1.0.0")
set(API_VFS_VERSION "2.7.0")
set(API_DATATYPE_VERSION "1.0.0")
set(API_EVENT_VERSION "1.0.0")

#### Project install for windows
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

# Install docs and licenses
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/README ${CMAKE_CURRENT_SOURCE_DIR}/COPYRIGHT ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE-THIRDPARTY
          DESTINATION /${CMAKE_PROJECT_NAME}/
          PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)

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
       MessageBox MB_YESNO \\\"Install Python 2.7.1 ? \\\" /SD IDYES IDNO endPython
        ExecWait '\\\"msiexec\\\" /i \\\"Prerequisites\\\\python-2.7.1.msi\\\" /passive'
        Goto endPython   
       endPython:
        MessageBox MB_YESNO \\\"Install PyQt 4.8.4-1 ? \\\" /SD IDYES IDNO endPyQt
        ExecWait '\\\"Prerequisites\\\\PyQt-Py2.7-x86-gpl-4.8.4-1.exe\\\"'
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

# Debian deb dependencies
#  python${PYTHON_VERSION} (>=${PYTHON_VERSION}.0), python-qt4 (>= 4.4.0), python-magic (>= 4.26)
# RedHat rpm dependencies
#  python >= ${PYTHON_VERSION}.0, PyQt4 >= 4.4.0, python-magic >= 4.26

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dff.py
  DESTINATION ${PYTHON_SITE_PACKAGES_PATH}/${CMAKE_PROJECT_NAME}
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

if (UNIX)
# Compress manpage
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/dff.1.gz
                     COMMAND ${GZIP_TOOL} -c ${CMAKE_CURRENT_SOURCE_DIR}/docs/dff.1 > ${CMAKE_CURRENT_BINARY_DIR}/dff.1.gz
                     COMMENT "Building dff.1.gz")
  add_custom_target(manpage ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/dff.1.gz)
# Install man page
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dff.1.gz
          DESTINATION ${CMAKE_INSTALL_ORIG_PREFIX}/share/man/man1
          PERMISSIONS OWNER_READ GROUP_READ WORLD_READ RENAME dff.1.gz)
# Install docs and licenses
  install(FILES README COPYRIGHT LICENSE LICENSE-THIRDPARTY
          DESTINATION ${CMAKE_INSTALL_ORIG_PREFIX}/share/doc/${CMAKE_PROJECT_NAME}-${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}
          PERMISSIONS OWNER_READ GROUP_READ WORLD_READ RENAME)
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

#### Subdirectories to recurse
add_subdirectory (api)
add_subdirectory (modules)
add_subdirectory (ui)
if (NOT UNIX AND WINALL)
  add_subdirectory (Prerequisites)
endif(NOT UNIX AND WINALL)

if (UNIX)
ADD_CUSTOM_COMMAND(
 	OUTPUT ${CMAKE_BINARY_DIR}/ctags
	COMMAND ctags --languages=+C++,+Python --exclude=[*.cxx,*wrap.h] --recurse=yes ${CMAKE_SOURCE_DIR}
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

ADD_CUSTOM_TARGET(tags DEPENDS ${CMAKE_BINARY_DIR}/ctags)
endif (UNIX)
