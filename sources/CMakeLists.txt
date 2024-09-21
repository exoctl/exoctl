set(FLAGS_OPTIMIZATIONS OFF)
set(FLAGS_DEBUG ON)

option(LIEF_TESTS "Build LIEF tests" OFF)

include_directories(
    ../include
    ../libraries
    ../sources
    ../
    ../libraries/tomlplusplus/include
    ../libraries/lief/include
    ../libraries/capstone-engine/include/
    ../libraries/signatures/include
)

file(GLOB_RECURSE SOURCES
    engine/crow/*.cxx
    engine/analysis/*/*.cxx
    engine/data/*.cxx
    engine/crypto/*.cxx
    engine/security/*/*.cxx
    engine/parser/*/*.cxx   
    engine/parser/*.cxx
    dto/*.cxx
    engine/database/*.cxx
    engine/*.cxx
)

add_executable(engine main.cxx)
target_sources(engine PUBLIC ${SOURCES})
target_link_libraries(engine PUBLIC 
    Crow::Crow 
    yara 
    spdlog::spdlog 
    sqlite3  
    nlohmann_json::nlohmann_json
    fmt
    LIEF::LIEF
    capstone
    signatures
    magic
    crypto
)

if(FLAGS_OPTIMIZATIONS)
    target_compile_options(engine PUBLIC
        -O2           
        -ftree-vectorize
        -mavx
	-fno-stack-protector
        -march=native
        -fdelete-null-pointer-checks
        -fdelete-dead-exceptions
    )
elseif(FLAGS_DEBUG)
    target_compile_options(engine PUBLIC
        -ggdb3
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
add_subdirectory(../libraries/json ${CMAKE_BINARY_DIR}/libraries/json)
add_subdirectory(../libraries/fmt ${CMAKE_BINARY_DIR}/libraries/fmt)
add_subdirectory(../libraries/lief ${CMAKE_BINARY_DIR}/libraries/lief)
add_subdirectory(../libraries/signatures ${CMAKE_BINARY_DIR}/libraries/signatures)
