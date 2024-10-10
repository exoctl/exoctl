cmake_minimum_required(VERSION 3.10)

project(EngineTests)

option(RAPIDJSON_BUILD_TESTS OFF)
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
    ../libraries/capstone-engine/include/
    ../libraries/lief/include
    ../libraries/googletest/googletest/include
    ../libraries/rapidjson/include/
    .
)

add_subdirectory(crypto/)
add_subdirectory(magic/)
add_subdirectory(disassembly/capstone/)
add_subdirectory(parser/)
add_subdirectory(security/yara/)
add_subdirectory(../libraries/fmt ${CMAKE_BINARY_DIR}/libraries/fmt)
add_subdirectory(../libraries/googletest/ ${CMAKE_BINARY_DIR}/libraries/googletest)
add_subdirectory(../libraries/capstone-engine/ ${CMAKE_BINARY_DIR}/libraries/capstone-engine)
add_subdirectory(../libraries/rapidjson ${CMAKE_BINARY_DIR}/libraries/rapidjson)
add_subdirectory(../libraries/tomlplusplus ${CMAKE_BINARY_DIR}/libraries/tomlplusplus)


add_executable(tests_engine tests_engine.cxx)
target_link_libraries(tests_engine
    tests_crypto
    tests_magic
    tests_capstone
    tests_toml
    tests_yara
    GTest::gtest
    fmt)
