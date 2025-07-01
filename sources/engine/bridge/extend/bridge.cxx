#include <engine/bridge/bridge.hxx>
#include <engine/bridge/extend/bridge.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine::bridge::extend
{
    void Bridge::bind_bridge(engine::lua::StateView &p_lua)
    {
        p_lua.new_usertype<bridge::Bridge>(
            "Bridge",
            sol::constructors<bridge::Bridge()>(),
            "setup",
            &bridge::Bridge::setup,
            "load",
            &bridge::Bridge::load);

        plugins::Plugins::lua.state["_analysis"] = bridge::Bridge::analysis;
    }

    void Bridge::lua_open_library(engine::lua::StateView &p_lua)
    {
        Bridge::bind_bridge(p_lua);
    }

    void Bridge::_plugins()
    {
        engine::bridge::endpoints::Analysis::plugins();

        Bridge::bind_bridge(plugins::Plugins::lua.state);
    }
} // namespace engine::bridge::extend