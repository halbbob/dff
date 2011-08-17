# - Find BFIO
# This module finds an installed BFIO.  It sets the following variables:
#  BFIO_FOUND - set to true if BFIO is found
#  BFIO_LIBRARY - dynamic libraries for aff
#  BFIO_INCLUDE_DIR - the path to the include files
#  BFIO_VERSION   - the version number of the aff library
#

SET(BFIO_FOUND FALSE)

FIND_LIBRARY(BFIO_LIBRARY bfio)

IF (BFIO_LIBRARY)
   FIND_PATH(BFIO_INCLUDE_FILE libbfio.h)
   IF (BFIO_INCLUDE_FILE)
      STRING(REPLACE "libbfio.h" "" BFIO_INCLUDE_DIR "${BFIO_INCLUDE_FILE}")
      FILE(WRITE ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/bfioversion.c
      "#include <libbfio.h>
       #include <stdio.h>
       int main()
       {
	 const char*   version;

	 version = libbfio_get_version();
  	 printf(\"%s\", version);
       }")
      TRY_RUN(BFIO_RUN_RESULT BFIO_COMP_RESULT
	${CMAKE_BINARY_DIR}
      	${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/bfioversion.c
	CMAKE_FLAGS -DINCLUDE_DIRECTORIES:STRING=${BFIO_INCLUDE_DIR} -DLINK_LIBRARIES:STRING=${BFIO_LIBRARY}
	COMPILE_DEFINITIONS "-DHAVE_STDINT_H -DHAVE_INTTYPES_H"
	COMPILE_OUTPUT_VARIABLE COMP_OUTPUT
	RUN_OUTPUT_VARIABLE RUN_OUTPUT)
      #message(STATUS ${BFIO_COMP_RESULT})
      #message(STATUS ${COMP_OUTPUT})
      #message(STATUS ${RUN_OUPUT})
      #message(STATUS ${BFIO_RUN_RESULT})
      IF (BFIO_COMP_RESULT)
      	 IF (BFIO_RUN_RESULT)
	    set(BFIO_FOUND TRUE)
	    SET(BFIO_VERSION ${RUN_OUTPUT})
	 ENDIF (BFIO_RUN_RESULT)
      ELSE (BFIO_COMP_RESULT)
      	   message(STATUS "${COMP_OUTPUT}")
      ENDIF (BFIO_COMP_RESULT)
   ENDIF (BFIO_INCLUDE_FILE)
ENDIF (BFIO_LIBRARY)