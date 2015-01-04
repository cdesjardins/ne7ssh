
set(net7ssh_LIB_SRCS
    crypt.cpp
    crypt.h
    ne7ssh.cpp
    ne7ssh.h
    ne7ssh_channel.cpp
    ne7ssh_channel.h
    ne7ssh_connection.cpp
    ne7ssh_connection.h
    ne7ssh_kex.cpp
    ne7ssh_kex.h
    ne7ssh_session.cpp
    ne7ssh_session.h
    ne7ssh_string.cpp
    ne7ssh_string.h
    ne7ssh_transport.cpp
    ne7ssh_transport.h
    ne7ssh_types.h
    ne7ssh_keys.cpp
    ne7ssh_keys.h
    ne7ssh_error.cpp
    ne7ssh_error.h
    ne7ssh_sftp.cpp
    ne7ssh_sftp.h
    ne7ssh_sftp_packet.cpp
    ne7ssh_sftp_packet.h
    ne7ssh_mutex.cpp
    ne7ssh_mutex.h)

include_directories ( src ${HAVE_BOTAN} )
add_definitions(-DNE7SSH_EXPORTS)
add_library(ne7ssh STATIC ${net7ssh_LIB_SRCS})

add_library(net7ssh SHARED ${net7ssh_LIB_SRCS})
target_link_libraries(net7ssh ${HAVE_BOTAN_LIB})
if(MSVC)
    target_link_libraries(net7ssh ws2_32)
    target_link_libraries(ne7ssh ws2_32)
endif()
set_target_properties(net7ssh PROPERTIES VERSION 0.3.1 SOVERSION 0)

install(TARGETS net7ssh  DESTINATION lib)
install(FILES ne7ssh.h ne7ssh_types.h ne7ssh_error.h ne7ssh_mutex.h DESTINATION include)

