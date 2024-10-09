file(GLOB_RECURSE SOURCES_JSON
    ../../sources/engine/parser/json.cxx
    json.cxx
)

file(GLOB_RECURSE SOURCES_TOML
    ../../sources/engine/parser/toml.cxx
    toml.cxx
)

add_library(benchmark_json json.cxx)
add_library(benchmark_toml toml.cxx)

target_sources(benchmark_json PUBLIC ${SOURCES_JSON})
target_sources(benchmark_toml PUBLIC ${SOURCES_TOML})

target_link_libraries(
    benchmark_json 
    benchmark::benchmark 
)

target_link_libraries(
    benchmark_toml             
    benchmark::benchmark       
) 
