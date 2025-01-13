include(ExternalProject)
set(LUA_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libraries/lua")
set(LUA_BUILD_DIR "${CMAKE_BINARY_DIR}/libraries/lua")

ExternalProject_Add(lua
    PREFIX ${CMAKE_BINARY_DIR}/_deps
    GIT_REPOSITORY "" 
    SOURCE_DIR ${LUA_SOURCE_DIR}
    CONFIGURE_COMMAND "" 
    BUILD_COMMAND make
    BUILD_ALWAYS true 
    BUILD_IN_SOURCE true  
    INSTALL_COMMAND ${CMAKE_COMMAND} -E make_directory ${LUA_BUILD_DIR} && 
                   ${CMAKE_COMMAND} -E copy ${LUA_SOURCE_DIR}/liblua.a ${LUA_BUILD_DIR}/liblua.a)


add_library(liblua STATIC IMPORTED)

set_target_properties(liblua PROPERTIES
    IMPORTED_LOCATION "${LUA_BUILD_DIR}/liblua.a"
)
