# The rendezvous daemon.
#
# Deployed by whoever operates the service. The Homebrew formula configures with
# -DDZ_BUILD_SERVER=OFF, so a user installing the client never builds this.

add_library(dz_server_core STATIC
    src/connection.cpp
    src/poller.cpp
    src/rate_limiter.cpp
    src/server.cpp
    src/session_table.cpp)

target_include_directories(dz_server_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(dz_server_core PUBLIC dz_common)

add_executable(drop-zone-server src/main.cpp)
target_link_libraries(drop-zone-server PRIVATE dz_server_core)
