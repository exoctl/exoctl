#pragma once

#include <engine/lua/lua.hxx>

namespace engine
{
    namespace interface
    {
        class ILuaOpenLibrary
        {
          public:
            virtual ~ILuaOpenLibrary() = default;
            virtual void lua_open_library(engine::lua::StateView &) = 0;
        };
    } // namespace interface
} // namespace engine