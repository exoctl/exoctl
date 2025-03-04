#ifdef ENGINE_PRO
#include <engine/bridge/bridge.hxx>
#include <engine/bridge/plugin/bridge.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine::bridge::plugin
{
    void Bridge::bind_bridge()
    {
        plugins::Plugins::lua.state.new_usertype<bridge::Bridge>(
            "Bridge",
            sol::constructors<bridge::Bridge()>(),
            "setup",
            &bridge::Bridge::setup,
            "load",
            &bridge::Bridge::load);
    }

    void Bridge::_plugins()
    {
        bridge::endpoints::Data::plugins();
        //m_analysis->register_plugins();
        Bridge::bind_bridge();
    }
} // namespace engine::bridge::plugin
#endif