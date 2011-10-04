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


FILE(GLOB dependencies ${CMAKE_CURRENT_BINARY_DIR} *)

foreach(file ${dependencies})
	message(STATUS ${file})
	IF (NOT IS_DIRECTORY(${file}))
		IF (NOT PYTHON_INSTALLER)
			STRING(REGEX MATCH "python.*" PYTHON_INSTALLER "${file}")
		ENDIF (NOT PYTHON_INSTALLER)
		IF (NOT PYQT_INSTALLER)
			STRING(REGEX MATCH "PyQt.*" PYQT_INSTALLER "${file}")
		ENDIF (NOT PYQT_INSTALLER)
		IF (NOT VCREDIST_INSTALLER)
			STRING(REGEX MATCH "vcredist.*" VCREDIST_INSTALLER "${file}")
		ENDIF (NOT VCREDIST_INSTALLER)
	ENDIF (NOT IS_DIRECTORY(${file}))
endforeach()
set(PYTHON_INSTALLER ${PYTHON_INSTALLER} PARENT_SCOPE)
set(PYQT_INSTALLER ${PYQT_INSTALLER} PARENT_SCOPE)
set(VCREDIST_INSTALLER ${VCREDIST_INSTALLER} PARENT_SCOPE)
	
set(dependencies_files
	${PYTHON_INSTALLER}
	${PYQT_INSTALLER}
	${VCREDIST_INSTALLER}
)

install_file(dependencies ${dependencies_files})
