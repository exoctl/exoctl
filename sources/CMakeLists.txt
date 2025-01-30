# Configuration flags
set(FLAGS_OPTIMIZATIONS OFF CACHE BOOL "Enable optimization flags")
set(FLAGS_DEBUG ON CACHE BOOL "Enable debug flags")
set(ENGINE_PRO ON BOOL "Enable Skull Pro flags")
set(BUILD_AS_LIBRARY OFF CACHE BOOL "Build as library instead of executable ")

# Include directories
include_directories(
    ../include
    ../libraries
    ../sources
    ../
    ../libraries/lua
    ../libraries/tomlplusplus/include
    ../libraries/rapidjson/include
    ../libraries/lief/include
    ../libraries/capstone-engine/include
    ../libraries/signatures/include
    ../libraries/llama/include
    ../libraries/llama/ggml/include
)

# Source files
file(GLOB_RECURSE SOURCES
    engine/server/*.cxx
    engine/analysis/*/*.cxx
    engine/data/*.cxx
    engine/crypto/*.cxx
    engine/security/*/*.cxx
    engine/parser/*/*.cxx
    engine/parser/*.cxx
    engine/database/*.cxx
    engine/*.cxx
    *.cxx
)

# Check if building as a library or executable
if(BUILD_AS_LIBRARY)
    add_library(engine SHARED ${SOURCES})
    message(STATUS "Building as a shared library")
else()
    add_executable(engine application/application.cxx)
    message(STATUS "Building as an executable")
endif()

# Add source files to the target
target_sources(engine PRIVATE ${SOURCES})

# Link libraries
target_link_libraries(engine PRIVATE
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
    stdc++
    signatures
    magic
    pthread
    crypto
)

# Add ENGINE_PRO flag if enabled
if(ENGINE_PRO)
    message(STATUS "Building with ENGINE_PRO enabled")
    target_compile_definitions(engine PRIVATE -DENGINE_PRO)
endif()

# Compiler flags for optimizations, debugging, and Skull Pro
if(FLAGS_OPTIMIZATIONS)
    message(STATUS "Building with optimizations enabled")
    target_compile_options(engine PRIVATE
        -O2
        -fmodules-ts
        -ftree-vectorize
        -mavx
        -fuse-ld=gold
        -ldl
        -fmodules-ts
        -fno-stack-protector
        -march=native
        -DCROW_OPENSSL
        -fdelete-null-pointer-checks
        -fdelete-dead-exceptions
    )
elseif(FLAGS_DEBUG)
    message(STATUS "Building with debug flags enabled")
    target_compile_options(engine PRIVATE
        -ggdb3
        -ldl
        -fuse-ld=gold
        -fmodules-ts
        -fms-extensions
        --all-warnings
        -fmodules-ts
        -DDEBUG
        -g
        -Warray-bounds
        -Werror
    )
endif()
