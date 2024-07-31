set(FLAGS_OPTIMIZATIONS ON)
set(FLAGS_DEBUG OFF)

file(GLOB_RECURSE SOURCES
    *.cxx
    ../scan/yara/*.cxx
    ../scan/*.cxx
    ../scan/hash/*.cxx
)

add_executable(engine-api crowsocket.cxx)
target_sources(engine-api PRIVATE ${SOURCES})
target_link_libraries(engine-api PUBLIC Crow::Crow)

if(FLAGS_OPTIMIZATIONS)
    target_compile_options(engine-api PUBLIC
        -O2           
        -ftree-vectorize
        -mavx
        -fno-stack-protector
        -march=native
        -fdelete-null-pointer-checks
        -fdelete-dead-exceptions
    )
elseif(FLAGS_DEBUG)
    target_compile_options(engine-api PUBLIC
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