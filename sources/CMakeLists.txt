# Configuration flags
set(FLAGS_OPTIMIZATIONS OFF CACHE BOOL "Enable optimization flags")
set(FLAGS_DEBUG ON CACHE BOOL "Enable debug flags")
set(ENGINE_PRO ON BOOL "Enable Infinity Pro flags")

# Include directories
include_directories(
    ../include
    ../libraries
    ../sources
    ../
    ../libraries/sol2/include
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

add_library(infinity SHARED ${SOURCES})

# Add source files to the target
target_sources(infinity PRIVATE ${SOURCES})

# Link libraries
target_link_libraries(infinity PRIVATE
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
    sol2
    pthread
    crypto
)

# Add ENGINE_PRO flag if enabled
if(ENGINE_PRO)
    message(STATUS "Building with ENGINE_PRO enabled")
    target_compile_definitions(infinity PRIVATE -DENGINE_PRO)
endif()

# Compiler flags for optimizations, debugging, and Infinity Pro
if(FLAGS_OPTIMIZATIONS)
    message(STATUS "Building with optimizations enabled")
    target_compile_options(infinity PRIVATE
        -O2
        -fmodules-ts
        -ftree-vectorize
        -mavx
        -fuse-ld=gold
        -ldl
        -fPIC
        -fmodules-ts
        -shared
        -DCROW_ENABLE_SSL
        -fno-stack-protector
        -march=native
        -fdelete-null-pointer-checks
        -fdelete-dead-exceptions
    )
elseif(FLAGS_DEBUG)
    message(STATUS "Building with debug flags enabled")
    target_compile_options(infinity PRIVATE
        -ggdb3
        -ldl
        -fPIC
        -fuse-ld=gold
        -shared
        -fmodules-ts
        -DCROW_ENABLE_SSL
        -fms-extensions
        --all-warnings
        -fmodules-ts
        -DDEBUG
        -g
        -Warray-bounds
        -Werror
    )
endif()
