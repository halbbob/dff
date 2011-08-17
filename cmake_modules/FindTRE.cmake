# - Find TRE
# This module finds an installed TRE.  It sets the following variables:
#  TRE_FOUND - set to true if TRE is found
#  TRE_LIBRARY - dynamic libraries for aff
#  TRE_INCLUDE_DIR - the path to the include files
#  TRE_VERSION   - the version number of the aff library
#

SET(TRE_FOUND FALSE)

FIND_LIBRARY(TRE_LIBRARY tre)

IF (TRE_LIBRARY)
   FIND_FILE(TRE_INCLUDE_FILE tre.h PATH_SUFFIXES tre)
   IF (TRE_INCLUDE_FILE)
      STRING(REPLACE "tre.h" "" TRE_INCLUDE_DIR "${TRE_INCLUDE_FILE}")
      FILE(WRITE ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/treconfig.c
      "#include <tre.h>
       #include <stdio.h>
       int main()
       {
	 char*   version;
	 int	 approx;
	 int	 wchar;
	 int	 mbs;

	 tre_config(TRE_CONFIG_VERSION, &version);
	 tre_config(TRE_CONFIG_APPROX, &approx);
	 tre_config(TRE_CONFIG_WCHAR, &wchar);
	 tre_config(TRE_CONFIG_MULTIBYTE, &mbs);
	 printf(\"%s--%d--%d--%d\", version, approx, wchar, mbs);
       }")
      TRY_RUN(TRE_RUN_RESULT TRE_COMP_RESULT
	${CMAKE_BINARY_DIR}
      	${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/treconfig.c
	CMAKE_FLAGS -DINCLUDE_DIRECTORIES:STRING=${TRE_INCLUDE_DIR} -DLINK_LIBRARIES:STRING=${TRE_LIBRARY}
	COMPILE_DEFINITIONS "-DHAVE_STDINT_H -DHAVE_INTTYPES_H"
	COMPILE_OUTPUT_VARIABLE COMP_OUTPUT
	RUN_OUTPUT_VARIABLE RUN_OUTPUT)
      IF (TRE_COMP_RESULT)
      	 IF (TRE_RUN_RESULT)
       	    STRING(REGEX REPLACE "([0-9]+\\.[0-9]+\\.[0-9]+)--[0-1]+--[0-1]+--[0-1]+.*" "\\1" TRE_VERSION "${RUN_OUTPUT}")
       	    STRING(REGEX REPLACE "[0-9]+\\.[0-9]+\\.[0-9]+--([0-1]+)--[0-1]+--[0-1]+.*" "\\1" TRE_HAVE_APPROX "${RUN_OUTPUT}")
       	    STRING(REGEX REPLACE "[0-9]+\\.[0-9]+\\.[0-9]+--[0-1]+--([0-1]+)--[0-1]+.*" "\\1" TRE_HAVE_WCHAR "${RUN_OUTPUT}")
       	    STRING(REGEX REPLACE "[0-9]+\\.[0-9]+\\.[0-9]+--[0-1]+--[0-1]+--([0-1]+).*" "\\1" TRE_HAVE_MULTIBYTE "${RUN_OUTPUT}")
	    SET(TRE_FOUND TRUE)
	 ENDIF (TRE_RUN_RESULT)
      ELSE (TRE_COMP_RESULT)
      	   message(STATUS "${COMP_OUTPUT}")
      ENDIF (TRE_COMP_RESULT)
   ENDIF (TRE_INCLUDE_FILE)
ENDIF (TRE_LIBRARY)