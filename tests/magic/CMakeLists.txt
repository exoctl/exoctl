file(GLOB_RECURSE SOURCES
    ../../sources/engine/magic/*.cxx
    ../../sources/engine/exception.cxx
    *.cxx
)

add_library(tests_magic magic.cxx)
target_sources(tests_magic PUBLIC ${SOURCES})
target_link_libraries(tests_magic  GTest::gtest fmt magic)
