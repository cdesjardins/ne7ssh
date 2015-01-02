include_directories ( ../src ${HAVE_BOTAN} )
add_executable( generateKeys generateKeys.cpp )
add_executable( getFile getFile.cpp )
add_executable( keyAuth keyAuth.cpp )
add_executable( multipleThreads multipleThreads.cpp )
add_executable( passwordAuth passwordAuth.cpp )
add_executable( sftpExample sftpExample.cpp )
target_link_libraries(generateKeys net7ssh ${HAVE_BOTAN_LIB})
target_link_libraries(getFile net7ssh ${HAVE_BOTAN_LIB})
target_link_libraries(keyAuth net7ssh ${HAVE_BOTAN_LIB})
target_link_libraries(multipleThreads net7ssh ${HAVE_BOTAN_LIB})
target_link_libraries(passwordAuth net7ssh ${HAVE_BOTAN_LIB})
target_link_libraries(sftpExample net7ssh ${HAVE_BOTAN_LIB})

install(DIRECTORY . DESTINATION share/doc/ne7ssh/examples)
install(TARGETS generateKeys getFile keyAuth multipleThreads passwordAuth sftpExample DESTINATION bin)


