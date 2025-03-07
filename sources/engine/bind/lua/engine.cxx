#include <engine/bridge/bridge.hxx>
#include <engine/configuration/configuration.hxx>
#include <engine/emergency/emergency.hxx>
#include <engine/engine.hxx>
#include <engine/interfaces/ibind.hxx>
#include <engine/logging/logging.hxx>
#include <engine/memory/memory.hxx>
#include <engine/server/server.hxx>
#include <vector>

extern "C" {
int luaopen_libinfinity(lua_State *L)
{
    sol::state_view lua(L);

    std::vector<std::unique_ptr<engine::interface::IBind>> bindings;

    bindings.reserve(5);

    bindings.push_back(std::make_unique<engine::server::extend::Server>());
    bindings.push_back(std::make_unique<engine::bridge::extend::Bridge>());
    bindings.push_back(std::make_unique<engine::memory::Memory>());
    bindings.push_back(
        std::make_unique<engine::configuration::extend::Configuration>());
    bindings.push_back(std::make_unique<engine::logging::extend::Logging>());
    bindings.push_back(std::make_unique<engine::Engine>());

    for (auto &bind : bindings) {
        bind->bind_to_lua(lua);
    }

    return 0;
}
}
