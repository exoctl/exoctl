cmake_minimum_required(VERSION 3.10)

project(EngineBenchmark)

set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable Google Benchmark testing")

option(RAPIDJSON_BUILD_TESTS "Build RapidJSON tests" OFF)
option(RAPIDJSON_BUILD_DOC "Build RapidJSON documentation" OFF)
option(RAPIDJSON_BUILD_EXAMPLES "Build RapidJSON examples" OFF)


include_directories(
    ../include
    ../libraries
    ../sources
    ../
    ../libraries/tomlplusplus/include
    ../libraries/lief/include
    ../libraries/benchmark/include
    ../libraries/rapidjson/include
    .
)


add_subdirectory(crypto/)
add_subdirectory(server/focades/data/)
add_subdirectory(parser/)
add_subdirectory(../libraries/fmt ${CMAKE_BINARY_DIR}/libraries/fmt)
add_subdirectory(../libraries/benchmark/ ${CMAKE_BINARY_DIR}/libraries/benchmark)
add_subdirectory(../libraries/rapidjson ${CMAKE_BINARY_DIR}/libraries/rapidjson)


add_executable(benchmark_engine benchmark_engine.cxx)
target_link_libraries(
    benchmark_engine
    benchmark::benchmark
    fmt
    benchmark_crypto
    benchmark_metadata
    benchmark_json
    benchmark_toml)
