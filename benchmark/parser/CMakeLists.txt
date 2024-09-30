file(GLOB_RECURSE SOURCES_JSON
    ../../sources/engine/parser/json.cxx
    json.cxx
)

file(GLOB_RECURSE SOURCES_TOML
    ../../sources/engine/parser/toml.cxx
    toml.cxx
)

set(SOURCE_FILE_PATH "${CMAKE_SOURCE_DIR}/../configuration.toml")
set(DESTINATION_DIRECTORY "${CMAKE_BINARY_DIR}")

# Comando para copiar o arquivo diretamente
file(COPY "${SOURCE_FILE_PATH}" DESTINATION "${DESTINATION_DIRECTORY}")

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
