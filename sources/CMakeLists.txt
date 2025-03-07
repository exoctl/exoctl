# Configuration flags
set(FLAGS_OPTIMIZATIONS ON)
set(ENGINE_PRO OFF)

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
if(${ENGINE_PRO})
    message(STATUS "[infinity] -- Building with ENGINE_PRO enabled")
    target_compile_definitions(infinity PRIVATE -DENGINE_PRO)
endif()

# Compiler flags for optimizations, debugging, and Infinity Pro
if(${FLAGS_OPTIMIZATIONS})
    message(STATUS "[infinity] -- Building with FLAGS_OPTIMIZATIONS enabled")
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
else()
    message(STATUS "[infinity] -- Building with FLAGS_OPTIMIZATIONS flags disabled")
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
