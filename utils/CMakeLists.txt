add_executable(p7b_append_cert)

target_sources(p7b_append_cert PRIVATE
    p7b_append_cert.cc
)

target_include_directories(p7b_append_cert PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(p7b_append_cert PRIVATE ${OPENSSL_LIBRARIES})

if(NOT UNIX)
# https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-shutdown
target_link_libraries(p7b_append_cert PRIVATE ws2_32.lib crypt32.lib)
endif(NOT UNIX)

add_executable(set_p7b_sig)

target_sources(set_p7b_sig PRIVATE
    set_p7b_sig.cc
)

target_include_directories(set_p7b_sig PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(set_p7b_sig PRIVATE ${OPENSSL_LIBRARIES})

if(NOT UNIX)
target_link_libraries(set_p7b_sig PRIVATE ws2_32.lib crypt32.lib)
endif(NOT UNIX)