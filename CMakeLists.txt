# Information cmake
cmake_minimum_required(VERSION 3.5.2)

# Information project
project(Engine VERSION 1.0.0 LANGUAGES CXX)
set(LIB_MAJOR_VERSION "1")
set(LIB_MINOR_VERSION "0")
set(LIB_PATCH_VERSION "0")

set(CMAKE_BUILD_TYPE "realese")
set(BUILD_TESTS OFF )
set(BUILD_BENCHMARK OFF )
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_PTHREADS_INIT 1)
set(THREADS_PREFER_PTHREAD_FLAG ON)

# add subdirectory
add_subdirectory( sources/ )

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory( tests/ )
endif()
if(BUILD_BENCHMARK)
	add_subdirectory( benchmark/ )
endif()