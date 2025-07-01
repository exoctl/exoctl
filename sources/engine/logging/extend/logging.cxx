#include <engine/logging/extend/logging.hxx>
#include <engine/logging/logging.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine::logging::extend
{
    void Logging::lua_open_library(engine::lua::StateView &p_lua)
    {
        Logging::bind_logging(p_lua);
    }

    void Logging::_plugins()
    {
        Logging::bind_logging(plugins::Plugins::lua.state);
    }

    void Logging::bind_logging(engine::lua::StateView &p_lua)
    {
        p_lua.new_usertype<logging::Logging>(
            "Logging",
            "new",
            sol::constructors<logging::Logging()>(),
            "load",
            &logging::Logging::load,
            "setup",
            &logging::Logging::setup,
            "info",
            static_cast<void (logging::Logging::*)(const std::string &)>(
                &logging::Logging::info),
            "warn",
            static_cast<void (logging::Logging::*)(const std::string &)>(
                &logging::Logging::warn),
            "critical",
            static_cast<void (logging::Logging::*)(const std::string &)>(
                &logging::Logging::critical),
            "debug",
            static_cast<void (logging::Logging::*)(const std::string &)>(
                &logging::Logging::debug),
            "error",
            static_cast<void (logging::Logging::*)(const std::string &)>(
                &logging::Logging::error));
    }

} // namespace engine::logging::extend