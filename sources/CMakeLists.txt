# Configuration flags
set(FLAGS_OPTIMIZATIONS OFF CACHE BOOL "Enable optimization flags")
set(FLAGS_DEBUG ON CACHE BOOL "Enable debug flags")

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

# Define the executable
add_executable(engine main.cxx)

# Add source files to the target
target_sources(engine PRIVATE ${SOURCES})

# Link libraries
target_link_libraries(engine PRIVATE
    Crow::Crow
    yara
    spdlog::spdlog
    llama
    sqlite3
    fmt
    LIEF::LIEF
    clamav
    liblua
    capstone
    ssl
    stdc++
    signatures
    magic
    pthread
    crypto
)

# Compiler flags for optimizations and debugging
if(FLAGS_OPTIMIZATIONS)
    message(STATUS "Building with optimizations enabled")
    target_compile_options(engine PRIVATE
        -O2
        -fmodules-ts
        -ftree-vectorize
        -mavx
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
        -fmodules-ts
        -fms-extensions
        --all-warnings
        -DDEBUG
        -g
        -Warray-bounds
        -Werror
    )
endif()