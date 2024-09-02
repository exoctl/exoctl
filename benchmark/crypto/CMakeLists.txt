file(GLOB_RECURSE SOURCES
    ../../sources/engine/crypto/*.cxx
    *.cxx
)

add_library(benchmark_crypto crypto.cxx)
target_sources(benchmark_crypto PUBLIC ${SOURCES})
target_link_libraries(benchmark_crypto benchmark::benchmark fmt crypto)