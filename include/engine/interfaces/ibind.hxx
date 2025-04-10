#pragma once

#include <engine/lua/lua.hxx>

namespace engine
{
    namespace interface
    {
        class IBind
        {
          public:
            virtual ~IBind() = default;
            virtual void bind_to_lua(engine::lua::StateView &) = 0;
        };
    } // namespace interface
} // namespace engine