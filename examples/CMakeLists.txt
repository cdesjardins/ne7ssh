include_directories ( ../src ${HAVE_BOTAN} )
add_definitions(-DNE7SSH_STATIC)
add_executable( generateKeys generateKeys.cpp )
add_executable( getFile getFile.cpp )
add_executable( keyAuth keyAuth.cpp )
add_executable( multipleThreads multipleThreads.cpp )
add_executable( passwordAuth passwordAuth.cpp )
add_executable( sftpExample sftpExample.cpp )
target_link_libraries(generateKeys ne7ssh ${HAVE_BOTAN_LIB})
target_link_libraries(getFile ne7ssh ${HAVE_BOTAN_LIB})
target_link_libraries(keyAuth ne7ssh ${HAVE_BOTAN_LIB})
target_link_libraries(multipleThreads ne7ssh ${HAVE_BOTAN_LIB})
target_link_libraries(passwordAuth ne7ssh ${HAVE_BOTAN_LIB})
target_link_libraries(sftpExample ne7ssh ${HAVE_BOTAN_LIB})

install(DIRECTORY . DESTINATION share/doc/ne7ssh/examples)
install(TARGETS generateKeys getFile keyAuth multipleThreads passwordAuth sftpExample DESTINATION bin)


