#include <engine/engine.hxx>

extern "C" {

int luaopen_libengine(lua_State *L)
{
    sol::state_view lua(L);

    engine::Engine engine;
    engine.bind_to_lua(lua);

    return 0;
}
}
