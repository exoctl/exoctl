file(GLOB_RECURSE SOURCES
    ../../../sources/engine/disassembly/*.cxx
    ../../../sources/engine/exception.cxx
    *.cxx
)

add_library(tests_capstone capstone.cxx)
target_sources(tests_capstone PUBLIC ${SOURCES})
target_link_libraries(tests_capstone  GTest::gtest fmt capstone)
