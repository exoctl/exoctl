set(FLAGS_OPTIMIZATIONS ON)
set(FLAGS_DEBUG OFF)


include_directories(
    ../include
    ../libraries
    ../sources
    ../
    ../libraries/tomlplusplus/include
    ../libraries/lief/include
)

file(GLOB_RECURSE SOURCES
    engine/crow/*.cxx
    engine/analysis/*/*.cxx
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
    pqxx 
    sqlite3  
    nlohmann_json::nlohmann_json
    fmt
    LIEF::LIEF
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
        --extra-warnings
    )
endif()

add_subdirectory(../libraries/crow ${CMAKE_BINARY_DIR}/libraries/crow)
add_subdirectory(../libraries/tomlplusplus ${CMAKE_BINARY_DIR}/libraries/tomlplusplus)
add_subdirectory(../libraries/spdlog ${CMAKE_BINARY_DIR}/libraries/spdlog)
add_subdirectory(../libraries/json ${CMAKE_BINARY_DIR}/libraries/json)
add_subdirectory(../libraries/fmt ${CMAKE_BINARY_DIR}/libraries/fmt)
add_subdirectory(../libraries/lief ${CMAKE_BINARY_DIR}/libraries/lief)