file(GLOB_RECURSE SOURCES
    ../../sources/engine/parser/toml.cxx
    ../../sources/engine/exception.cxx
    toml.cxx
)

add_library(tests_toml toml.cxx)
target_sources(tests_toml PUBLIC ${SOURCES})
target_link_libraries(tests_toml  GTest::gtest fmt)