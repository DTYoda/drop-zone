cmake_minimum_required(VERSION 3.16)

project(drop-zone
        VERSION 1.0.0
        DESCRIPTION "Peer-to-peer terminal file transfer with a storage-free rendezvous server"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Build options
# ---------------------------------------------------------------------------

# Homebrew bottles are compiled once and installed on many different machines,
# so `-march=native` must stay opt-in: a bottle built with AVX-512 crashes with
# SIGILL on an older CPU. Every CPU-specific fast path in drop-zone is selected
# at run time instead (see common/src/cpu.cpp), so leaving this OFF costs
# nothing measurable.
option(DZ_NATIVE_ARCH "Compile for the host CPU (-march=native). Do not use for redistributable builds." OFF)
option(DZ_BUILD_CLIENT "Build the drop-zone client binary" ON)
option(DZ_BUILD_SERVER "Build the drop-zone-server rendezvous daemon" ON)
option(DZ_BUILD_TESTS  "Build the unit tests" ON)
option(DZ_LTO "Enable link-time optimisation for release builds" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

find_package(OpenSSL 1.1.1 REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Shared compile settings
#
# Exposed as an INTERFACE target so the client, the server and the tests all
# agree on warnings and optimisation without repeating the flag list.
# ---------------------------------------------------------------------------

add_library(dz_flags INTERFACE)

target_compile_options(dz_flags INTERFACE
    -Wall -Wextra -Wpedantic
    -Wshadow -Wconversion -Wsign-conversion
    -Wnon-virtual-dtor -Woverloaded-virtual
    $<$<CONFIG:Release>:-O3>
    $<$<CONFIG:RelWithDebInfo>:-O2>
    # Hiding non-exported symbols shrinks the dynamic symbol table and lets the
    # optimiser prove that internal functions have no external callers.
    -fvisibility=hidden -fvisibility-inlines-hidden)

if(NOT APPLE)
    # -fno-plt removes a level of indirection from every call into libcrypto,
    # which the AEAD hot loop makes millions of times. Not supported by the
    # Apple linker.
    target_compile_options(dz_flags INTERFACE $<$<CONFIG:Release>:-fno-plt>)
endif()

if(DZ_NATIVE_ARCH)
    target_compile_options(dz_flags INTERFACE -march=native -mtune=native)
endif()

if(DZ_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT dz_ipo_ok OUTPUT dz_ipo_why)
    if(dz_ipo_ok)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    else()
        message(STATUS "drop-zone: link-time optimisation unavailable (${dz_ipo_why})")
    endif()
endif()

# Every platform-specific syscall wrapper is guarded by one of these.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(dz_flags INTERFACE DZ_PLATFORM_LINUX=1 _GNU_SOURCE=1)
elseif(APPLE)
    target_compile_definitions(dz_flags INTERFACE DZ_PLATFORM_MACOS=1)
else()
    message(WARNING "drop-zone: untested platform '${CMAKE_SYSTEM_NAME}', falling back to portable POSIX paths")
endif()

target_compile_definitions(dz_flags INTERFACE
    DZ_VERSION_STRING="${PROJECT_VERSION}")

# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------

add_subdirectory(common)

if(DZ_BUILD_CLIENT)
    add_subdirectory(client)
endif()

if(DZ_BUILD_SERVER)
    add_subdirectory(server)
endif()

if(DZ_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Installation
#
# The Homebrew formula configures with -DDZ_BUILD_SERVER=OFF, so a `brew
# install` only ever places the client and its manual page on the machine.
# ---------------------------------------------------------------------------

if(DZ_BUILD_CLIENT)
    install(TARGETS drop-zone RUNTIME DESTINATION bin)
endif()

if(DZ_BUILD_SERVER)
    install(TARGETS drop-zone-server RUNTIME DESTINATION bin)
endif()

message(STATUS "drop-zone ${PROJECT_VERSION}: build=${CMAKE_BUILD_TYPE} client=${DZ_BUILD_CLIENT} "
               "server=${DZ_BUILD_SERVER} tests=${DZ_BUILD_TESTS} native-arch=${DZ_NATIVE_ARCH}")
