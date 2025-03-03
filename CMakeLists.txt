cmake_minimum_required(VERSION 3.10)
project(SimpleBlockchain)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-Wall -Wextra -O2")

option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)

if (ENABLE_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=address")
elseif (ENABLE_TSAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=thread")
elseif (ENABLE_UBSAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fsanitize=undefined")
endif()

include_directories(include)
file(GLOB SOURCES src/*.c)

add_executable(blockchain ${SOURCES})

find_package(OpenSSL REQUIRED)
if (NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found. Install OpenSSL and try again.")
endif()

if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(CHECK_LIBRARY ${CMAKE_SOURCE_DIR}/lib/libcheck-aarch64.so)
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    set(CHECK_LIBRARY ${CMAKE_SOURCE_DIR}/lib/libcheck-x86_64.so)
else()
    message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()


target_link_libraries(blockchain OpenSSL::Crypto ${CHECK_LIBRARY})

set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")