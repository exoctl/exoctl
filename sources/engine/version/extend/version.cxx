#ifdef ENGINE_PRO

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
            "version",
            &version::Version::version,
            "code",
            sol::var(CODE),
            "major",
            sol::var(MAJOR),
            "patchlevel",
            sol::var(PATCHLEVEL),
            "sublevel",
            sol::var(SUBLEVEL));
    }
} // namespace engine::version::extend

#endif