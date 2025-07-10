cmake_minimum_required(VERSION 3.16)
project(exoctl VERSION 1.2.0 LANGUAGES CXX)

# Global settings
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build options
option(FLAGS_OPTIMIZATIONS "Enable compiler optimizations" ON)

# Library versioning
set(LIB_SOVERSION 1)

# Include external configuration (e.g., dependencies)
include(../include/CMakeLists.txt)

# Dependencies list (shared between lib and executable if needed)
set(EXOCTL_DEPENDENCIES
    Crow::Crow
    liblua
    yara
    spdlog::spdlog
    llama
    sqlite3
    fmt
    LIEF::LIEF
    clamav
    capstone
    ssl
    magic
    sol2
    pthread
    crypto
)

# === Helper Function: Compiler flags ===
function(set_compile_flags target)
    if(FLAGS_OPTIMIZATIONS)
        message(STATUS "[exoctl] -- Building ${target} with optimizations")
        target_compile_options(${target} PRIVATE
            -O2
            -fmodules-ts
            -ftree-vectorize
            -DCROW_ENABLE_SSL
            -mavx
        )
    else()
        message(STATUS "[exoctl] -- Building ${target} with debug flags")
        target_compile_options(${target} PRIVATE
            -ggdb3
            -fmodules-ts
            -Wall
            -Wextra
            -Werror
            -DCROW_ENABLE_SSL
            -Warray-bounds
        )
        target_compile_definitions(${target} PRIVATE DEBUG)
    endif()
endfunction()

# === Source files ===
file(GLOB_RECURSE EXOCTL_SOURCES
    engine/server/*.cxx
    engine/analysis/*/*.cxx
    engine/data/*.cxx
    engine/crypto/*.cxx
    engine/security/*/*.cxx
    engine/parser/*/*.cxx
    engine/database/*.cxx
    engine/version/*/*.cxx
    engine/*.cxx
    *.cxx
)

file(GLOB_RECURSE APP_SOURCES app/*.cxx)

# === Build Shared Library ===
add_library(exoctl SHARED ${EXOCTL_SOURCES})

set_target_properties(exoctl PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${LIB_SOVERSION}
    OUTPUT_NAME exoctl
)

target_link_libraries(exoctl PUBLIC ${EXOCTL_DEPENDENCIES})
set_compile_flags(exoctl)

# === Build Executable ===
add_executable(appexoctl ${APP_SOURCES})

# Link the library to the executable
target_link_libraries(appexoctl PRIVATE exoctl)
set_compile_flags(appexoctl)

