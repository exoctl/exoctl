cmake_minimum_required(VERSION 3.10)

project(EngineTests)

set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include_directories(
    ../include
    ../libraries
    ../sources
    ../
    ../libraries/tomlplusplus/include
    ../libraries/lief/include
    ../libraries/googletest/googletest/include
    .
)

add_subdirectory(crypto/)
# add_subdirectory(data/)
# add_subdirectory(parser/)
add_subdirectory(../libraries/fmt ${CMAKE_BINARY_DIR}/libraries/fmt)
add_subdirectory(../libraries/googletest/ ${CMAKE_BINARY_DIR}/libraries/googletest)
# add_subdirectory(../libraries/json ${CMAKE_BINARY_DIR}/libraries/json)


add_executable(tests_engine tests_engine.cxx)
target_link_libraries(tests_engine
    tests_crypto
    GTest::gtest
    fmt)
