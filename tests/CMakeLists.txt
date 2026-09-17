# Unit tests, plus registration of the end-to-end script.

add_executable(dz_tests
    main.cpp
    test_frame.cpp
    test_crypto.cpp
    test_manifest.cpp
    test_keystore.cpp
    test_reliable_udp.cpp)

target_link_libraries(dz_tests PRIVATE dz_client_core dz_server_core)

add_test(NAME unit COMMAND dz_tests)

# The end-to-end test needs both binaries and a free port, so it is registered
# separately and can be skipped with `ctest -E e2e`.
add_test(NAME e2e
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/e2e_loopback.sh ${CMAKE_BINARY_DIR} 16)
set_tests_properties(e2e PROPERTIES TIMEOUT 600)
