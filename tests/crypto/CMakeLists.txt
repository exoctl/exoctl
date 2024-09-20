file(GLOB_RECURSE SOURCES
    ../../sources/engine/crypto/*.cxx
    *.cxx
)

add_library(tests_crypto crypto.cxx)
target_sources(tests_crypto PUBLIC ${SOURCES})
target_link_libraries(tests_crypto  GTest::gtest fmt crypto)