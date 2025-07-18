#include <engine/plugins/plugins.hxx>
#include <engine/version/extend/version.hxx>
#include <engine/version/version.hxx>

namespace engine::version::extend
{
    void Version::_plugins()
    {
        Version::bind_version();
    }

    void Version::bind_version()
    {
        plugins::Plugins::lua.state.new_usertype<version::Version>(
            "Version",
            sol::constructors<version::Version()>(),
            "check",
            &version::Version::check,
            "code",
            sol::var(ENGINE_CODE),
            "major",
            sol::var(ENGINE_MAJOR),
            "minor",
            sol::var(ENGINE_MINOR),
            "patch",
            sol::var(ENGINE_PATCH));
    }
} // namespace engine::version::extend