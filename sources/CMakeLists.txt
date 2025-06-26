# Configuration flags
set(FLAGS_OPTIMIZATIONS ON)
set(LIB_VERSION 1.2.0)
set(LIB_SOVERSION 1)

include(../include/CMakeLists.txt)

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
    engine/version/*/*.cxx
    engine/*.cxx
    *.cxx
)

add_library(exoctl SHARED ${SOURCES})
set_target_properties(exoctl PROPERTIES
    VERSION ${LIB_VERSION}
    SOVERSION ${LIB_SOVERSION}
)

# Add source files to the target
target_sources(exoctl PRIVATE ${SOURCES})

# Link libraries
target_link_libraries(exoctl PRIVATE
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
    magic
    sol2
    pthread
    crypto
)

# Compiler flags for optimizations, debugging, and exoctl
if(${FLAGS_OPTIMIZATIONS})
    message(STATUS "[exoctl] -- Building with FLAGS_OPTIMIZATIONS enabled")
    target_compile_options(exoctl PRIVATE
        -O1
        -fmodules-ts
        -ftree-vectorize
        -mavx
        -fuse-ld=gold
        -ldl
        -fPIC
        -fmodules-ts
        -shared
        -DCROW_ENABLE_SSL
    )
else()
    message(STATUS "[exoctl] -- Building with FLAGS_OPTIMIZATIONS flags disabled")
    target_compile_options(exoctl PRIVATE
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
