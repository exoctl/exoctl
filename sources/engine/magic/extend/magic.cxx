#include <engine/magic/extend/magic.hxx>
#include <engine/magic/magic.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine::magic::extend
{
    void Magic::bind_magic()
    {
        plugins::Plugins::lua.state.new_usertype<magic::Magic>(
            "Magic",
            sol::constructors<magic::Magic()>(),
            "mime",
            &magic::Magic::mime);
    }

    void Magic::_plugins()
    {
        Magic::bind_magic();
    }
} // namespace engine::magic::extend