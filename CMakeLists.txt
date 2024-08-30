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
set(CXXFLAGS "-std=c++20")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_PTHREADS_INIT 1)
set(THREADS_PREFER_PTHREAD_FLAG ON)

# add subdirectory
add_subdirectory( sources/ )

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory( tests/ )
else()
  option(LIEF_TESTS "Build LIEF tests" OFF)
endif()
if(BUILD_BENCHMARK)
	add_subdirectory( benchmark/ )
endif()