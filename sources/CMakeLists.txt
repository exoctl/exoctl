include_directories(
    ../include
    ../libraries
    ../sources
    ../
    ../interfaces
    ../libraries/tomlplusplus/include
    ../libraries/libpqxx/include/
)

set(FLAGS_OPTIMIZATIONS ON)
set(FLAGS_DEBUG OFF)

file(GLOB_RECURSE SOURCES
    crow/*.cxx
    scan/*/*.cxx
    scan/*.cxx
    parser/*/*.cxx
    parser/*.cxx
    dto/*/*.cxx
    database/*/*.cxx
    log/*.cxx
)

add_executable(engine engine.cxx)
target_sources(engine PUBLIC ${SOURCES})
target_link_libraries(engine PUBLIC Crow::Crow yara 
                                    spdlog::spdlog pqxx sqlite3  
                                    nlohmann_json::nlohmann_json)

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

# add subdirectory libraries
add_subdirectory(../libraries/crow libraries/crow)
add_subdirectory(../libraries/tomlplusplus libraries/tomlplusplus)
add_subdirectory(../libraries/spdlog libraries/spdlog)
add_subdirectory(../libraries/json libraries/json)
add_subdirectory(../libraries/libpqxx libraries/libpqxx)