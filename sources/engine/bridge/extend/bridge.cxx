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

        plugins::Plugins::lua.state["_data"] = bridge::Bridge::data;
        plugins::Plugins::lua.state["_analysis"] = bridge::Bridge::analysis;
    }

    void Bridge::bind_to_lua(engine::lua::StateView &p_lua)
    {
        Bridge::bind_bridge(p_lua);
    }

#ifdef ENGINE_PRO
    void Bridge::_plugins()
    {
        bridge::endpoints::Data::plugins();
        engine::bridge::endpoints::Analysis::plugins();

        Bridge::bind_bridge(plugins::Plugins::lua.state);
    }
#endif
} // namespace engine::bridge::extend