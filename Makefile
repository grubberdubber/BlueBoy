# BlueBoy — convenience wrapper around the out-of-tree CMake build.
#
#   make              configure + build (Release) into ./build/blueboy
#   make test         build and run the unit suite
#   make run ARGS="…" build and run with arguments
#   make install      sudo cmake --install build
#   make clean        remove ./build
#
# The build must stay out of tree: `cmake --build .` at the repository root is
# not a build directory and will fail by design.

BUILD_DIR  ?= build
BUILD_TYPE ?= Release
JOBS       ?= $(shell nproc 2>/dev/null || echo 2)
BIN        := $(BUILD_DIR)/blueboy
ARGS       ?=

.PHONY: all configure build test run install clean

all: build

configure:
	cmake -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)

build: configure
	cmake --build $(BUILD_DIR) -j$(JOBS)

test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure

run: build
	./$(BIN) $(ARGS)

install: build
	sudo cmake --install $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
