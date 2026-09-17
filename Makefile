# Convenience wrapper around CMake.
#
# The real build description lives in CMakeLists.txt; this file exists so that
# the familiar `make`, `make clean` and `make test` still work from a fresh
# checkout without anybody having to remember the configure incantation.

BUILD_DIR   ?= build
BUILD_TYPE  ?= Release
CMAKE_FLAGS ?=
JOBS        ?= $(shell (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null) || echo 4)

.PHONY: all configure build test install clean distclean format help

all: build

## configure: generate the build system in $(BUILD_DIR)
configure: $(BUILD_DIR)/CMakeCache.txt

$(BUILD_DIR)/CMakeCache.txt:
	cmake -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) $(CMAKE_FLAGS)

## build: compile the client, the server and the tests
build: configure
	cmake --build $(BUILD_DIR) --parallel $(JOBS)

## test: run the unit test suite
test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure

## e2e: run the loopback end-to-end transfer test across every transport tier
e2e: build
	./tests/e2e_loopback.sh $(BUILD_DIR)

## install: install the client into $(DESTDIR)$(PREFIX)
install: build
	cmake --install $(BUILD_DIR)

## clean: remove compiled objects but keep the configured build tree
clean:
	@if [ -d $(BUILD_DIR) ]; then cmake --build $(BUILD_DIR) --target clean; fi

## distclean: remove the build tree entirely
distclean:
	rm -rf $(BUILD_DIR)

## help: list the available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
