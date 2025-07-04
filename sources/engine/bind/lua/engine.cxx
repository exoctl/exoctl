#include <engine/bridge/bridge.hxx>
#include <engine/configuration/configuration.hxx>
#include <engine/engine.hxx>
#include <engine/interfaces/iluaopenlibrary.hxx>
#include <engine/logging/logging.hxx>

#include <engine/database/database.hxx>
#include <engine/server/server.hxx>

extern "C" {
int luaopen_build_sources_libexoctl(lua_State *L)
{
    engine::lua::StateView lua(L);

    engine::database::extend::Database database;
    database.lua_open_library(lua);

    engine::server::extend::Server server;
    server.lua_open_library(lua);

    engine::bridge::extend::Bridge bridge;
    bridge.lua_open_library(lua);

    engine::configuration::extend::Configuration config;
    config.lua_open_library(lua);

    engine::logging::extend::Logging log;
    log.lua_open_library(lua);

    engine::Engine engine;
    engine.lua_open_library(lua);

    return EXIT_SUCCESS;
}
}
