# Code shared by the client and the rendezvous server.
#
# Built as a static library so both binaries are self-contained apart from
# libcrypto: a Homebrew-installed client should not need a drop-zone shared
# object on the library path.

add_library(dz_common STATIC
    src/aead_pool.cpp
    src/cpu.cpp
    src/crypto.cpp
    src/error.cpp
    src/fileio.cpp
    src/frame.cpp
    src/log.cpp
    src/protocol.cpp
    src/secure.cpp)

target_include_directories(dz_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(dz_common
    PUBLIC dz_flags OpenSSL::Crypto Threads::Threads)
