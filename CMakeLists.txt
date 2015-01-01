cmake_minimum_required(VERSION 2.0)
project(net7ssh CXX)
INCLUDE(CheckIncludeFileCXX)
set(CMAKE_REQUIRED_INCLUDES "${BOTAN_DIR}/include")
check_include_file_cxx("botan/botan.h" HAVE_BOTAN)
if (NOT HAVE_BOTAN)
    MESSAGE(FATAL_ERROR "Could not find Botan includes.")
endif()
find_library(HAVE_BOTAN_LIB NAMES botan PATHS "${BOTAN_DIR}/lib")
if (NOT HAVE_BOTAN_LIB)
    MESSAGE(FATAL_ERROR "Could not find Botan library")
endif()

if(MSVC)
    # Force to always compile with W4
    if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
        string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    else()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
    endif()
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_CLANGXX OR CMAKE_COMPILER_IS_CLANGCC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
endif()

set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/install")
include_directories ( src ${CMAKE_REQUIRED_INCLUDES} )

add_subdirectory ( src )
add_subdirectory ( examples )

########### install files ###############

install(FILES LICENSE.QPL AUTHORS INSTALL COPYING CHANGELOG DESTINATION share/doc/ne7ssh)
install(DIRECTORY doc DESTINATION share/doc/ne7ssh)
install(DIRECTORY doc/html DESTINATION share/doc/ne7ssh)
