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