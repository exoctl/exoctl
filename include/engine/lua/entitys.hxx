#pragma once

#include <sol/sol.hpp>
#include <string>

namespace engine::lua
{
    using StateView = sol::state_view;
    using Env = sol::environment;

    namespace record::script
    {
        using Type = enum Type {
            SCRIPT_FILE,
            SCRIPT_BUFF
        };

        /*the important order*/
        using Plugin = struct Script {
            std::string path;
            std::string name;
            Type type;
            Env env;
        };
    } // namespace record::script
} // namespace engine::lua
