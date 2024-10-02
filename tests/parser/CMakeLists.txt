file(GLOB_RECURSE SOURCES
    ../../sources/engine/parser/toml.cxx
    ../../sources/engine/exception.cxx
    toml.cxx
)


set(SOURCE_FILE_PATH "${CMAKE_SOURCE_DIR}/../configuration.toml")
set(DESTINATION_DIRECTORY "${CMAKE_BINARY_DIR}")

# Comando para copiar o arquivo diretamente
file(COPY "${SOURCE_FILE_PATH}" DESTINATION "${DESTINATION_DIRECTORY}")


add_library(tests_toml toml.cxx)
target_sources(tests_toml PUBLIC ${SOURCES})
target_link_libraries(tests_toml  GTest::gtest fmt)
