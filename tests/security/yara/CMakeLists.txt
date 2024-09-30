file(GLOB_RECURSE SOURCES
    ../../../sources/engine/security/yara/*.cxx
    ../../../sources/engine/exception.cxx
    *.cxx
)

add_library(tests_yara yara.cxx)
target_sources(tests_yara PUBLIC ${SOURCES})
target_link_libraries(tests_yara  GTest::gtest fmt yara)
