cmake_minimum_required(VERSION 3.15)
project(BlueBoy VERSION 1.0.0 LANGUAGES CXX)

# Set CMake policies
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()
if(POLICY CMP0074)
    cmake_policy(SET CMP0074 NEW)
endif()

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -DDEBUG")

# Note: Include directories will be set per target below

# Find required packages
find_package(PkgConfig REQUIRED)

# Find Boost using modern CMake approach
# Set policy to use new Boost module behavior
cmake_policy(PUSH)
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()
find_package(Boost REQUIRED COMPONENTS system filesystem program_options)
cmake_policy(POP)

if(NOT Boost_FOUND)
    message(FATAL_ERROR "Boost not found")
endif()

# Find BlueZ
pkg_check_modules(BLUEZ REQUIRED bluez)

# Find libpcap
find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found")
endif()

# Source files (using CONFIGURE_DEPENDS for better dependency tracking)
file(GLOB_RECURSE CORE_SOURCES CONFIGURE_DEPENDS "src/core/*.cpp")
file(GLOB_RECURSE MODULE_SOURCES CONFIGURE_DEPENDS "src/modules/*.cpp")
file(GLOB_RECURSE UTIL_SOURCES CONFIGURE_DEPENDS "src/utils/*.cpp")

# Main executable
add_executable(blueboy
    src/main.cpp
    ${CORE_SOURCES}
    ${MODULE_SOURCES}
    ${UTIL_SOURCES}
)

# Link libraries
target_link_libraries(blueboy
    ${Boost_LIBRARIES}
    ${BLUEZ_LIBRARIES}
    ${PCAP_LIBRARY}
    pthread
)

# Include directories for target
target_include_directories(blueboy PRIVATE
    include
    src
    ${Boost_INCLUDE_DIRS}
    ${BLUEZ_INCLUDE_DIRS}
)

# Install target
install(TARGETS blueboy DESTINATION bin)

# Install documentation
install(FILES README.md DESTINATION share/doc/blueboy)
install(DIRECTORY docs/ DESTINATION share/doc/blueboy/docs)

# Create build directories
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/output)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/logs)
