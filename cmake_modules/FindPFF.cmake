# - Find PFF
# This module finds an installed PFF.  It sets the following variables:
#  PFF_FOUND - set to true if PFF is found
#  PFF_LIBRARY - dynamic libraries for aff
#  PFF_INCLUDE_DIR - the path to the include files
#  PFF_VERSION   - the version number of the aff library
#

SET(PFF_FOUND FALSE)

FIND_LIBRARY(PFF_LIBRARY pff)

IF (PFF_LIBRARY)
   FIND_FILE(PFF_INCLUDE_FILE libpff.h)
   IF (PFF_INCLUDE_FILE)
      STRING(REPLACE "libpff.h" "" PFF_INCLUDE_DIR "${PFF_INCLUDE_FILE}")
      message(STATUS "LIBPFF include path found ${PFF_INCLUDE_DIR}")
      FILE(WRITE ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/pffversion.c
      "#include <libpff.h>
       #include <stdio.h>
       int main()
       {
	 const char*   version;

	 version = libpff_get_version();
  	 printf(\"%s\", version);
       }")
      TRY_RUN(PFF_RUN_RESULT PFF_COMP_RESULT
	${CMAKE_BINARY_DIR}
      	${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/pffversion.c
	CMAKE_FLAGS -DINCLUDE_DIRECTORIES:STRING=${PFF_INCLUDE_DIR} -DLINK_LIBRARIES:STRING=${PFF_LIBRARY}
	COMPILE_DEFINITIONS "-DHAVE_STDINT_H -DHAVE_INTTYPES_H"
	COMPILE_OUTPUT_VARIABLE COMP_OUTPUT
	RUN_OUTPUT_VARIABLE RUN_OUTPUT)
      IF (PFF_COMP_RESULT)
      	 IF (PFF_RUN_RESULT)
	    SET(PFF_FOUND TRUE)
	    SET(PFF_VERSION ${RUN_OUTPUT})
	 ENDIF (PFF_RUN_RESULT)
      ELSE (PFF_COMP_RESULT)
      	   message(STATUS "${COMP_OUTPUT}")
      ENDIF (PFF_COMP_RESULT)
   ENDIF (PFF_INCLUDE_FILE)
ENDIF (PFF_LIBRARY)