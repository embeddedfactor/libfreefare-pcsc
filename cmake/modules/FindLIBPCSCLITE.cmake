# $Id$
# TODO locate using pkg-config for linux/bsd

#set(LIBPCSCLITE_INCLUDE_DIRS "")
#set(LIBPCSCLITE_LIBRARIES "")
set(LIBPCSCLITE_INSTALL_DIR $ENV{PROGRAMFILES}/libpcsclite CACHE PATH "libpcsclite installation directory")

message("libpcsclite install dir: " ${LIBPCSCLITE_INSTALL_DIR})

find_path(LIBPCSCLITE_INCLUDE_DIRS NAMES PCSC/winscard.h PATHS ${LIBPCSCLITE_INSTALL_DIR}/include)
message("libpcsclite include dir found:  " ${LIBPCSCLITE_INCLUDE_DIRS})

if(${CMAKE_SYSTEM_NAME} STREQUAL Linux)
  find_library(LIBPCSCLITE_LIBRARIES libpcsclite.so.1 PATHS ${LIBPCSCLITE_INSTALL_DIR}/lib)
else()
  find_library(LIBPCSCLITE_LIBRARIES libpcsclite PATHS ${LIBPCSCLITE_INSTALL_DIR}/lib)
endif()
message("libpcsclite library found:  " ${LIBPCSCLITE_LIBRARIES})

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LIBPCSCLITE DEFAULT_MSG
  LIBPCSCLITE_INCLUDE_DIRS
  LIBPCSCLITE_LIBRARIES
)
MARK_AS_ADVANCED(LIBPCSCLITE_INCLUDE_DIRS LIBPCSCLITE_LIBRARIES)
