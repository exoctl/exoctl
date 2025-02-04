# CMake configuration
cmake_minimum_required(VERSION 3.5.2)

# Project information
project(Engine 
    VERSION 1.0.0 
    LANGUAGES CXX
)

# Build settings
set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries")

# Threading support
set(THREADS_PREFER_PTHREAD_FLAG ON)
set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_PTHREADS_INIT 1)

# Feature toggles
option(BUILD_TESTS "Build test suite" OFF)
option(BUILD_BENCHMARK "Build benchmark suite" OFF)
option(LIEF_DOC "Build LIEF documentation" OFF)
option(LIEF_PYTHON_API "Enable LIEF Python API" OFF)
option(LIEF_EXAMPLES "Build LIEF examples" OFF)
option(LIEF_TESTS "Enable LIEF tests" OFF)
option(RAPIDJSON_BUILD_TESTS "Build RapidJSON tests" OFF)
option(RAPIDJSON_BUILD_DOC "Build RapidJSON documentation" OFF)
option(RAPIDJSON_BUILD_EXAMPLES "Build RapidJSON examples" OFF)
option(LUABRIDGE_TESTING "Build LuaBdige Testing" OFF)

# External dependencies
include(cmake/lua_library.cmake)
add_subdirectory(libraries/llama ${CMAKE_BINARY_DIR}/libraries/llama)
add_subdirectory(libraries/capstone-engine ${CMAKE_BINARY_DIR}/libraries/capstone-engine)
add_subdirectory(libraries/crow ${CMAKE_BINARY_DIR}/libraries/crow)
add_subdirectory(libraries/tomlplusplus ${CMAKE_BINARY_DIR}/libraries/tomlplusplus)
add_subdirectory(libraries/spdlog ${CMAKE_BINARY_DIR}/libraries/spdlog)
add_subdirectory(libraries/fmt ${CMAKE_BINARY_DIR}/libraries/fmt)
add_subdirectory(libraries/signatures ${CMAKE_BINARY_DIR}/libraries/signatures)
add_subdirectory(libraries/jwt ${CMAKE_BINARY_DIR}/libraries/jwt)
add_subdirectory(libraries/lief ${CMAKE_BINARY_DIR}/libraries/lief)
add_subdirectory(libraries/rapidjson ${CMAKE_BINARY_DIR}/libraries/rapidjson)
add_subdirectory(libraries/sol2 ${CMAKE_BINARY_DIR}/libraries/sol2)


# Add project sources
add_subdirectory(sources)