cmake_minimum_required(VERSION 3.16)
project(BlueBoy VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O2 -pipe -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g3 -Wall -Wextra -Wpedantic")

find_package(Threads REQUIRED)
find_library(BLUETOOTH_LIB NAMES bluetooth REQUIRED)

# Optional: query BlueZ through its supported D-Bus API (sd-bus) instead of
# legacy HCI calls. The build still works without libsystemd.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(SYSTEMD QUIET IMPORTED_TARGET libsystemd>=240)
endif()

file(GLOB_RECURSE BLUEBOY_CORE CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/core/*.cpp)
file(GLOB_RECURSE BLUEBOY_MODULES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/modules/*.cpp)

# Core logic lives in a library so the unit tests can link it without main().
add_library(blueboy_core STATIC ${BLUEBOY_CORE})
target_include_directories(blueboy_core PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(blueboy_core PUBLIC ${BLUETOOTH_LIB} Threads::Threads)

if(TARGET PkgConfig::SYSTEMD)
    target_link_libraries(blueboy_core PUBLIC PkgConfig::SYSTEMD)
    target_compile_definitions(blueboy_core PUBLIC BLUEBOY_HAVE_SDBUS=1)
    message(STATUS "BlueBoy: sd-bus support enabled (BlueZ D-Bus API)")
else()
    message(STATUS "BlueBoy: sd-bus not found, D-Bus features disabled")
endif()

add_executable(blueboy src/main.cpp ${BLUEBOY_MODULES})
target_link_libraries(blueboy PRIVATE blueboy_core)

option(BLUEBOY_BUILD_TESTS "Build the unit test suite" ON)
if(BLUEBOY_BUILD_TESTS)
    enable_testing()
    add_executable(blueboy_tests tests/test_core.cpp)
    target_link_libraries(blueboy_tests PRIVATE blueboy_core)
    add_test(NAME core COMMAND blueboy_tests)
endif()

install(TARGETS blueboy RUNTIME DESTINATION bin)
install(FILES config/default.conf config/scope.conf config/advisories.conf
        DESTINATION share/blueboy)
