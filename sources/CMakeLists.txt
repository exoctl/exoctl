set(FLAGS_OPTIMIZATIONS OFF)
set(FLAGS_DEBUG ON)

include_directories(
    ../include
    ../libraries
    ../sources
    ../
    ../libraries/tomlplusplus/include
    ../libraries/rapidjson/include
    ../libraries/lief/include
    ../libraries/capstone-engine/include/
    ../libraries/signatures/include
    ../libraries/llama/include/
    ../libraries/llama/ggml/include
)

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

add_executable(engine main.cxx)
target_sources(engine PUBLIC ${SOURCES})
target_link_libraries(engine PUBLIC 
    Crow::Crow 
    yara 
    spdlog::spdlog 
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

if(FLAGS_OPTIMIZATIONS)
    target_compile_options(engine PUBLIC
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
    target_compile_options(engine PUBLIC
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

add_subdirectory(../libraries/capstone-engine ${CMAKE_BINARY_DIR}/libraries/capstone-engine)
add_subdirectory(../libraries/crow ${CMAKE_BINARY_DIR}/libraries/crow)
add_subdirectory(../libraries/tomlplusplus ${CMAKE_BINARY_DIR}/libraries/tomlplusplus)
add_subdirectory(../libraries/spdlog ${CMAKE_BINARY_DIR}/libraries/spdlog)
add_subdirectory(../libraries/fmt ${CMAKE_BINARY_DIR}/libraries/fmt)
add_subdirectory(../libraries/lief ${CMAKE_BINARY_DIR}/libraries/lief)
add_subdirectory(../libraries/signatures ${CMAKE_BINARY_DIR}/libraries/signatures)
add_subdirectory(../libraries/rapidjson ${CMAKE_BINARY_DIR}/libraries/rapidjson )
add_subdirectory(../libraries/jwt ${CMAKE_BINARY_DIR}/libraries/jwt )
add_subdirectory( ../libraries/llama/ ${CMAKE_BINARY_DIR}/libraries/llama )