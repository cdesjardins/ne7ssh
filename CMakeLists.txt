cmake_minimum_required(VERSION 2.0)
project(net7ssh CXX)
INCLUDE(CheckIncludeFileCXX)
set(CMAKE_REQUIRED_INCLUDES "${BOTAN_DIR}/include")
check_include_file_cxx("botan/botan.h" HAVE_BOTAN)
if (NOT ${HAVE_BOTAN})
    MESSAGE(FATAL_ERROR "Could not find Botan library.")
endif()
find_library(HAVE_BOTAN_LIB botan "${BOTAN_DIR}/lib")
MESSAGE(STATUS ${HAVE_BOTAN_LIB})
set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/install")
include_directories ( src ${CMAKE_REQUIRED_INCLUDES} )

add_subdirectory ( src )
add_subdirectory ( examples )

########### install files ###############

install(FILES LICENSE.QPL AUTHORS INSTALL COPYING CHANGELOG DESTINATION share/doc/ne7ssh)
install(DIRECTORY doc DESTINATION share/doc/ne7ssh)
install(DIRECTORY doc/html DESTINATION share/doc/ne7ssh)
