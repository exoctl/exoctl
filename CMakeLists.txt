# Information cmake
cmake_minimum_required(VERSION 3.5.2)

# Information project
project(Engine 
        VERSION 1.0.0 
        LANGUAGES 
        CXX)

set(CMAKE_BUILD_TYPE "realese")
set(BUILD_TESTS OFF )
set(BUILD_BENCHMARK OFF )
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_PTHREADS_INIT 1)
set(THREADS_PREFER_PTHREAD_FLAG ON)

# add subdirectory
add_subdirectory(libraries/capstone-engine ${CMAKE_BINARY_DIR}/libraries/capstone-engine)
add_subdirectory(libraries/crow ${CMAKE_BINARY_DIR}/libraries/crow)
add_subdirectory(libraries/tomlplusplus ${CMAKE_BINARY_DIR}/libraries/tomlplusplus)
add_subdirectory(libraries/spdlog ${CMAKE_BINARY_DIR}/libraries/spdlog)
add_subdirectory(libraries/fmt ${CMAKE_BINARY_DIR}/libraries/fmt)
add_subdirectory(libraries/lief ${CMAKE_BINARY_DIR}/libraries/lief)
add_subdirectory(libraries/signatures ${CMAKE_BINARY_DIR}/libraries/signatures)
add_subdirectory(libraries/rapidjson ${CMAKE_BINARY_DIR}/libraries/rapidjson )
add_subdirectory(libraries/jwt ${CMAKE_BINARY_DIR}/libraries/jwt )
add_subdirectory(libraries/llama/ ${CMAKE_BINARY_DIR}/libraries/llama )
add_subdirectory( sources/ )
