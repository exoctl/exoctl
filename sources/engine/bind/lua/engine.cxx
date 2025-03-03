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
int luaopen_libskull(lua_State *L)
{
    sol::state_view lua(L);

    std::vector<std::unique_ptr<engine::interface::IBind>> bindings;

    bindings.reserve(6);

    bindings.push_back(std::make_unique<engine::server::plugin::Server>());
    bindings.push_back(std::make_unique<engine::bridge::Bridge>());
    bindings.push_back(std::make_unique<engine::memory::Memory>());
    bindings.push_back(
        std::make_unique<engine::configuration::plugin::Configuration>());
    bindings.push_back(std::make_unique<engine::logging::plugin::Logging>());
    bindings.push_back(std::make_unique<engine::Engine>());

    for (auto &bind : bindings) {
        bind->bind_to_lua(lua);
    }

    return 0;
}
}
