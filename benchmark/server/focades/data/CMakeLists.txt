file(GLOB_RECURSE SOURCES
    ../../../../sources/engine/bridge/focades/data/*.cxx
    ../../../../sources/engine/magic/*.cxx
    ../../../../sources/engine/crypto/*.cxx
    ../../../../sources/engine/dto/*.cxx
    ../../../../sources/engine/parser/json.cxx
    ../../../../sources/engine/exception.cxx
    *.cxx
)

add_library(benchmark_metadata metadata.cxx)
target_sources(benchmark_metadata PUBLIC ${SOURCES})
target_link_libraries(benchmark_metadata benchmark::benchmark fmt magic)