# The client: the binary a user installs with Homebrew.
#
# Split into a static library plus a thin main.cpp so the tests can link the same
# code the binary runs.

add_library(dz_client_core STATIC
    src/channel.cpp
    src/cli.cpp
    src/config.cpp
    src/identity.cpp
    src/known_peers.cpp
    src/manifest.cpp
    src/pipeline.cpp
    src/progress.cpp
    src/receiver.cpp
    src/reliable_udp.cpp
    src/rendezvous.cpp
    src/sender.cpp
    src/transport.cpp
    src/transport_relay.cpp
    src/transport_tcp.cpp)

target_include_directories(dz_client_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(dz_client_core PUBLIC dz_common)

add_executable(drop-zone src/main.cpp)
target_link_libraries(drop-zone PRIVATE dz_client_core)
